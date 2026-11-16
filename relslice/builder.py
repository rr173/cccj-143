"""Snapshot builder: external sort, per-row column trees, streaming row tree.

Build pipeline (the full input relation is never resident in memory):

1. rows are validated and spilled into sorted chunk files under a byte budget;
2. a k-way heap merge yields rows in full-coordinate order;
3. each row's cells, per-row column tree and row-tree leaf are persisted;
4. the row tree is assembled level by level from stored sibling digests;
5. the builder independently re-verifies counts, ordering, uniqueness, every
   column root, every row leaf and the final row-tree root before emitting
   the trusted root credential.
"""

from __future__ import annotations

import json
import os
import shutil

from . import encoding as E
from . import trees
from .encoding import EncodingError
from .ordering import (
    delete_chunks,
    merge_chunks,
    new_tmpdir,
    write_sorted_chunks,
)
from .root import (
    build_root_dict,
    new_snapshot_id,
    new_token_auth_key,
)
from .storage import Store


class BuildError(ValueError):
    pass


def build_snapshot(
    db_path: str,
    schema,
    rows,
    snapshot_id: str | None = None,
    chunk_bytes: int = 8 * 1024 * 1024,
) -> dict:
    if os.path.exists(db_path):
        raise BuildError(f"database already exists: {db_path}")
    snapshot_id = snapshot_id or new_snapshot_id()
    # Per-snapshot secret for continuation tokens.  Deliberately never stored
    # in the distributor database; it only appears in the trusted root file.
    token_auth_key = new_token_auth_key()
    tmpdir = new_tmpdir()
    store = Store.create(db_path)
    try:
        try:
            chunk_paths = write_sorted_chunks(
                rows, schema, tmpdir, chunk_bytes
            )
        except (ValueError, EncodingError) as exc:
            raise BuildError(str(exc)) from exc
        n_rows = 0
        try:
            for key_values, row_id, values in merge_chunks(chunk_paths, schema):
                _persist_row(store, n_rows, key_values, row_id, values, schema)
                n_rows += 1
            store.commit()
        except ValueError as exc:
            raise BuildError(str(exc)) from exc
        delete_chunks(chunk_paths, tmpdir)

        row_root = _build_row_tree(store, n_rows)
        store.put_meta("schema", schema.to_dict())
        store.put_meta("snapshot_id", snapshot_id)
        store.put_meta("protocol_id", E.PROTOCOL_ID.decode("ascii"))
        store.put_meta("n_rows", str(n_rows))
        store.put_meta("row_tree_root", E.hex32(row_root))
        store.commit()

        _self_verify(
            store, schema, n_rows, row_root, snapshot_id, token_auth_key
        )
        return build_root_dict(
            snapshot_id, schema, n_rows, row_root, token_auth_key
        )
    except Exception:
        store.close()
        if os.path.exists(db_path):
            os.remove(db_path)
        for suffix in ("-wal", "-shm"):
            side = db_path + suffix
            if os.path.exists(side):
                os.remove(side)
        # Remove any spilled sort chunks and the temporary directory.
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    finally:
        try:
            store.close()
        except Exception:
            pass


def _persist_row(store: Store, pos: int, key_values, row_id, values, schema):
    col_root, col_nodes = trees.build_column_tree(
        list(key_values), row_id, values
    )
    key_enc = b"".join(E.encode_value(v) for v in key_values)
    row_leaf = trees.row_leaf_digest(pos, list(key_values), row_id, col_root)
    store.insert_leaf(pos, row_id, key_enc, col_root, row_leaf)
    for col_idx, value in enumerate(values):
        store.insert_cell(pos, col_idx, E.encode_value(value))
    for (level, idx), digest in col_nodes.items():
        store.insert_col_node(pos, level, idx, digest)
    if (pos + 1) % 4096 == 0:
        store.commit()


def _build_row_tree(store: Store, n_rows: int) -> bytes:
    """Assemble the row tree from stored leaves; returns the root digest."""
    if n_rows == 0:
        root = trees.empty_digest("row", 0, 0)
        store.insert_row_node(0, 0, root)
        store.commit()
        return root
    level = 0
    count = n_rows
    while count > 1:
        parent_count = (count + 1) // 2
        for idx in range(parent_count):
            left_pos = 2 * idx
            right_pos = 2 * idx + 1
            left = _row_digest_at(store, level, left_pos)
            if right_pos < count:
                right = _row_digest_at(store, level, right_pos)
            else:
                right = trees.empty_digest("row", level, right_pos)
            digest = trees.internal_digest(
                "row", level + 1, idx, left, right
            )
            store.insert_row_node(level + 1, idx, digest)
        store.commit()
        count = parent_count
        level += 1
    return _row_digest_at(store, level, 0)


def _row_digest_at(store: Store, level: int, idx: int) -> bytes:
    if level == 0:
        return store.get_leaf(idx)[3]
    return store.get_row_node(level, idx)


def _self_verify(store: Store, schema, n_rows, row_root, snapshot_id,
                 token_auth_key):
    """Independent build-time verification of every authenticated invariant."""
    stored_n = store.total_rows
    if stored_n != n_rows:
        raise BuildError("self-check: row count mismatch")

    prev_key, prev_rid = None, None
    recomputed_leaves: list[bytes] = []
    for pos, row_id, key_enc, col_root, row_leaf in store.iter_all_positions():
        if pos != len(recomputed_leaves):
            raise BuildError("self-check: non-contiguous leaf positions")
        key_values = store.decode_key(key_enc)
        # ordering + duplicate full-coordinate check
        if prev_key is not None:
            from .ordering import coord_less

            if not coord_less(
                schema, prev_key, prev_rid, key_values, row_id
            ):
                raise BuildError("self-check: rows not strictly ordered")
        prev_key, prev_rid = key_values, row_id

        stored_cells = store.iter_cells(pos)
        if len(stored_cells) != schema.column_count:
            raise BuildError("self-check: cell count mismatch")
        values = [E.decode_value(enc) for _, enc in stored_cells]
        rebuilt_root, rebuilt_nodes = trees.build_column_tree(
            list(key_values), row_id, values
        )
        if rebuilt_root != col_root:
            raise BuildError(f"self-check: column root mismatch at pos {pos}")
        # every stored column node must equal the recomputed one
        stored_col = store.conn.execute(
            "SELECT level, idx, digest FROM colnodes WHERE pos=?", (pos,)
        ).fetchall()
        if len(stored_col) != len(rebuilt_nodes):
            raise BuildError("self-check: column node count mismatch")
        for lvl, idx, digest in stored_col:
            if digest != rebuilt_nodes[(lvl, idx)]:
                raise BuildError("self-check: column node digest mismatch")
        rebuilt_leaf = trees.row_leaf_digest(
            pos, list(key_values), row_id, col_root
        )
        if rebuilt_leaf != row_leaf:
            raise BuildError(f"self-check: row leaf mismatch at pos {pos}")
        recomputed_leaves.append(rebuilt_leaf)

    check_root, check_nodes = trees.build_tree("row", recomputed_leaves) \
        if recomputed_leaves else (
            trees.empty_digest("row", 0, 0), {}
        )
    if check_root != row_root:
        raise BuildError("self-check: row tree root mismatch")
    # row node table contents must match the recomputed tree
    stored_row_nodes = store.iter_row_nodes()
    if recomputed_leaves:
        if len(stored_row_nodes) != len(check_nodes) - n_rows:
            raise BuildError("self-check: row node table size mismatch")
        for lvl, idx, digest in stored_row_nodes:
            if check_nodes[(lvl, idx)] != digest:
                raise BuildError("self-check: stored row node mismatch")
    else:
        if len(stored_row_nodes) != 1 or stored_row_nodes[0][2] != row_root:
            raise BuildError("self-check: empty snapshot root node mismatch")

    root_obj = build_root_dict(
        snapshot_id, schema, n_rows, row_root, token_auth_key
    )
    meta_root = store.get_meta_text("row_tree_root")
    if meta_root != E.hex32(row_root):
        raise BuildError("self-check: meta root mismatch")
    if root_obj["snapshot_id"] != snapshot_id:
        raise BuildError("self-check: snapshot id mismatch")
