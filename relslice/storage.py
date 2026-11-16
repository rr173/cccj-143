"""SQLite-backed authenticated snapshot storage with real read counters.

The distributor only ever reads this database through :class:`Store`.  Every
index-node, row-leaf and cell access increments a dedicated counter, so the
narrow-page read budget can be measured honestly rather than asserted.

Tables::

    meta     : snapshot identity, protocol id, schema JSON, row count, roots
    leaves   : pos (PK), row_id (UNIQUE), encoded business key,
               column-tree root, row-tree leaf digest
    cells    : (pos, col_idx) PK, canonical encoded cell value
    rownodes : (level, idx) PK, row-tree internal node digest
    colnodes : (pos, level, idx) PK, per-row column-tree node digest

Leaf-level digests also live in ``leaves``/``colnodes`` (column leaves are
reconstructible from cells but are cached in colnodes level 0).
"""

from __future__ import annotations

import json
import sqlite3
import struct

from .encoding import decode_value, encode_value
from .schema import Schema


class ReadCounters:
    __slots__ = (
        "row_leaf_reads",
        "row_node_reads",
        "col_node_reads",
        "cell_reads",
    )

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.row_leaf_reads = 0
        self.row_node_reads = 0
        self.col_node_reads = 0
        self.cell_reads = 0

    def as_dict(self) -> dict:
        return {
            "row_leaf_reads": self.row_leaf_reads,
            "row_node_reads": self.row_node_reads,
            "col_node_reads": self.col_node_reads,
            "cell_reads": self.cell_reads,
            "total": (
                self.row_leaf_reads
                + self.row_node_reads
                + self.col_node_reads
                + self.cell_reads
            ),
        }


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.counters = ReadCounters()
        self._schema: Schema | None = None

    # ------------------------------------------------------------------ setup
    @staticmethod
    def create(path: str) -> "Store":
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB);
            CREATE TABLE leaves (
                pos INTEGER PRIMARY KEY,
                row_id INTEGER NOT NULL UNIQUE,
                key_enc BLOB NOT NULL,
                col_root BLOB NOT NULL,
                row_leaf BLOB NOT NULL
            );
            CREATE TABLE cells (
                pos INTEGER NOT NULL,
                col_idx INTEGER NOT NULL,
                enc BLOB NOT NULL,
                PRIMARY KEY (pos, col_idx)
            );
            CREATE TABLE rownodes (
                level INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                digest BLOB NOT NULL,
                PRIMARY KEY (level, idx)
            );
            CREATE TABLE colnodes (
                pos INTEGER NOT NULL,
                level INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                digest BLOB NOT NULL,
                PRIMARY KEY (pos, level, idx)
            );
            """
        )
        conn.commit()
        conn.close()
        return Store(path)

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------- meta
    def put_meta(self, key: str, value) -> None:
        if not isinstance(value, (bytes, str)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", (key, value)
        )

    def get_meta_text(self, key: str) -> str:
        cur = self.conn.execute("SELECT v FROM meta WHERE k=?", (key,))
        row = cur.fetchone()
        if row is None:
            raise KeyError(key)
        return row[0]

    def get_meta_json(self, key: str):
        return json.loads(self.get_meta_text(key))

    @property
    def schema(self) -> Schema:
        if self._schema is None:
            self._schema = Schema.from_dict(self.get_meta_json("schema"))
        return self._schema

    @property
    def total_rows(self) -> int:
        return int(self.get_meta_text("n_rows"))

    @property
    def snapshot_id(self) -> str:
        return self.get_meta_text("snapshot_id")

    # -------------------------------------------------------------- bulk load
    def insert_leaf(self, pos, row_id, key_enc, col_root, row_leaf) -> None:
        try:
            self.conn.execute(
                "INSERT INTO leaves(pos, row_id, key_enc, col_root, row_leaf)"
                " VALUES (?, ?, ?, ?, ?)",
                (pos, row_id, key_enc, col_root, row_leaf),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"duplicate or invalid row_id {row_id}: {exc}")

    def insert_cell(self, pos, col_idx, enc) -> None:
        self.conn.execute(
            "INSERT INTO cells(pos, col_idx, enc) VALUES (?, ?, ?)",
            (pos, col_idx, enc),
        )

    def insert_row_node(self, level, idx, digest) -> None:
        self.conn.execute(
            "INSERT INTO rownodes(level, idx, digest) VALUES (?, ?, ?)",
            (level, idx, digest),
        )

    def insert_col_node(self, pos, level, idx, digest) -> None:
        self.conn.execute(
            "INSERT INTO colnodes(pos, level, idx, digest)"
            " VALUES (?, ?, ?, ?)",
            (pos, level, idx, digest),
        )

    def commit(self) -> None:
        self.conn.commit()

    # ------------------------------------------------------------- page reads
    def get_leaf(self, pos: int):
        """Return (row_id, key_enc, col_root, row_leaf) for one position."""
        cur = self.conn.execute(
            "SELECT row_id, key_enc, col_root, row_leaf FROM leaves"
            " WHERE pos=?",
            (pos,),
        )
        row = cur.fetchone()
        if row is None:
            raise IndexError(f"leaf position {pos} does not exist")
        self.counters.row_leaf_reads += 1
        return row

    def get_cell_encoded(self, pos: int, col_idx: int) -> bytes:
        cur = self.conn.execute(
            "SELECT enc FROM cells WHERE pos=? AND col_idx=?",
            (pos, col_idx),
        )
        row = cur.fetchone()
        if row is None:
            raise IndexError(f"cell pos={pos} col={col_idx} does not exist")
        self.counters.cell_reads += 1
        return row[0]

    def get_cell(self, pos: int, col_idx: int):
        return decode_value(self.get_cell_encoded(pos, col_idx))

    def get_row_node(self, level: int, idx: int) -> bytes:
        cur = self.conn.execute(
            "SELECT digest FROM rownodes WHERE level=? AND idx=?",
            (level, idx),
        )
        row = cur.fetchone()
        if row is None:
            raise IndexError(f"row node ({level},{idx}) does not exist")
        self.counters.row_node_reads += 1
        return row[0]

    def get_col_node(self, pos: int, level: int, idx: int) -> bytes:
        cur = self.conn.execute(
            "SELECT digest FROM colnodes WHERE pos=? AND level=? AND idx=?",
            (pos, level, idx),
        )
        row = cur.fetchone()
        if row is None:
            raise IndexError(
                f"column node pos={pos} ({level},{idx}) does not exist"
            )
        self.counters.col_node_reads += 1
        return row[0]

    # --------------------------------------------------------- full scans for
    # ----------------------------------------------------------- build checks
    def iter_all_positions(self):
        cur = self.conn.execute(
            "SELECT pos, row_id, key_enc, col_root, row_leaf FROM leaves"
            " ORDER BY pos"
        )
        for row in cur:
            yield row

    def iter_cells(self, pos: int):
        cur = self.conn.execute(
            "SELECT col_idx, enc FROM cells WHERE pos=? ORDER BY col_idx",
            (pos,),
        )
        return cur.fetchall()

    def iter_row_nodes(self):
        cur = self.conn.execute(
            "SELECT level, idx, digest FROM rownodes ORDER BY level, idx"
        )
        return cur.fetchall()

    # ------------------------------------------------------------ key decode
    def decode_key(self, key_enc: bytes) -> tuple[object, ...]:
        schema = self.schema
        n_key = len(schema.key_names)
        values = []
        pos = 0
        for _ in range(n_key):
            tag = key_enc[pos]
            start = pos
            pos += 1
            if tag != 0x00:  # all non-null payloads are length framed
                (length,) = struct.unpack_from(">I", key_enc, pos)
                pos += 4 + length
            values.append(decode_value(key_enc[start:pos]))
        if pos != len(key_enc):
            raise ValueError("corrupt stored key encoding")
        return tuple(values)

    # ------------------------------------------------------------- positioning
    def lower_bound(self, key: tuple[object, ...], row_id: int) -> int:
        """First position whose full coordinate is >= (key, row_id).

        Iterative binary search over the position-ordered leaf table: each
        probe costs one row-leaf read, so positioning is O(log N) reads and
        the distributor never relies on unauthenticated min/max labels.
        """
        n = self.total_rows
        lo, hi = 0, n
        schema = self.schema
        while lo < hi:
            mid = (lo + hi) // 2
            mid_rid, mid_key_enc, _, _ = self.get_leaf(mid)
            mid_key = self.decode_key(mid_key_enc)
            if _coord_less(schema, mid_key, mid_rid, key, row_id):
                lo = mid + 1
            else:
                hi = mid
        return lo


def _coord_less(schema: Schema, key_a, rid_a, key_b, rid_b) -> bool:
    from .ordering import compare_scalar

    key_cols = [c for c in schema.columns if c.key]
    for idx, col in enumerate(key_cols):
        cmp = compare_scalar(key_a[idx], key_b[idx], col.col_type)
        if cmp:
            return cmp < 0
    return rid_a < rid_b
