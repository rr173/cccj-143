"""Distributor-side paging: range slicing with minimal authenticated proofs.

A page is produced without scanning the snapshot.  The only storage accesses
are:

* O(log N) row-leaf reads for binary-search positioning;
* one row-leaf read per returned row and at most two boundary neighbours;
* O(log N) row-tree proof nodes (shared sibling paths merged automatically);
* one cell read per projected cell;
* O(m log(C+1)) column-tree proof nodes per returned row for m projected
  columns.

Unprojected cell values never leave the database: their leaf digests are
only reachable through the column inclusion proofs.
"""

from __future__ import annotations

from . import encoding as E
from . import trees
from .query import Query
from .root import read_continuation_fields
from .storage import Store

INT64_MIN = -(1 << 63)
PAGE_FORMAT = "relslice-page"
PAGE_VERSION = 1


class PagerError(ValueError):
    pass


def open_store(db_path: str) -> Store:
    return Store(db_path)


def _continuation_body(snapshot_id, low, high, next_key, next_row_id) -> dict:
    return {
        "format": "relslice-continuation",
        "version": 1,
        "protocol_id": E.PROTOCOL_ID.decode("ascii"),
        "snapshot_id": snapshot_id,
        "low": [E.value_to_wire(v) for v in low],
        "high": [E.value_to_wire(v) for v in high],
        "next_key": [E.value_to_wire(v) for v in next_key],
        "next_row_id": next_row_id,
    }


def generate_page(store: Store, query: Query, continuation: dict | None = None):
    schema = store.schema
    n_rows = store.total_rows
    snap_id = store.snapshot_id
    store.counters.reset()

    anchor_key, anchor_rid = None, None
    if continuation is not None:
        c_snap, c_low, c_high, anchor_key, anchor_rid = (
            read_continuation_fields(continuation)
        )
        if c_snap != snap_id:
            raise PagerError("continuation belongs to another snapshot")
        if c_low != query.low or c_high != query.high:
            raise PagerError(
                "continuation is bound to a different [low, high) range"
            )
        start_pos = store.lower_bound(tuple(anchor_key), anchor_rid)
    else:
        start_pos = store.lower_bound(tuple(query.low), INT64_MIN)

    end_pos = store.lower_bound(tuple(query.high), INT64_MIN)
    # low > high is a legal empty range: no coordinate can satisfy both
    # bounds, so clamp the window to empty rather than treating it as an
    # internal error.
    if end_pos < start_pos:
        end_pos = start_pos

    stop = min(start_pos + query.page_length, end_pos)
    rows_out = []
    projected_idx = [schema.index(name) for name in query.projection]

    for pos in range(start_pos, stop):
        row_id, key_enc, _col_root, _row_leaf = store.get_leaf(pos)
        key_values = store.decode_key(key_enc)
        values = {}
        for name, col_idx in zip(query.projection, projected_idx):
            values[name] = store.get_cell(pos, col_idx)
        rows_out.append(
            {
                "pos": pos,
                "key": [E.value_to_wire(v) for v in key_values],
                "row_id": row_id,
                "values": {
                    name: E.value_to_wire(v) for name, v in values.items()
                },
            }
        )

    # Boundary neighbours (coordinate + column-root digest only).  Even a
    # zero-row page keeps the stubs adjacent to the located window so that
    # the verifier can prove the range genuinely contains no rows.
    predecessor = _stub(store, start_pos - 1) if start_pos > 0 else None
    successor = _stub(store, stop) if stop < n_rows else None

    exhausted = stop == end_pos
    next_token = None
    if not exhausted:
        nxt_rid, nxt_key_enc, _, _ = store.get_leaf(stop)
        nxt_key = store.decode_key(nxt_key_enc)
        # The keyless distributor emits only the unsigned token body.  The
        # client adds the keyed MAC from its trusted root before storing it.
        next_token = _continuation_body(
            snap_id, query.low, query.high, nxt_key, nxt_rid
        )

    row_proof, column_proofs = _build_proofs(
        store, schema, n_rows, rows_out, predecessor, successor, projected_idx
    )

    page = {
        "format": PAGE_FORMAT,
        "version": PAGE_VERSION,
        "protocol_id": E.PROTOCOL_ID.decode("ascii"),
        "snapshot_id": snap_id,
        "query": query.to_dict(),
        "continuation_in": continuation,
        "n_rows": n_rows,
        "start_pos": start_pos,
        "rows": rows_out,
        "predecessor": predecessor,
        "successor": successor,
        "exhausted": exhausted,
        "row_proof": row_proof,
        "column_proofs": column_proofs,
        "next_continuation": next_token,
    }
    page["read_counts"] = store.counters.as_dict()
    return page


def _stub(store: Store, pos: int) -> dict:
    row_id, key_enc, col_root, _ = store.get_leaf(pos)
    key_values = store.decode_key(key_enc)
    return {
        "pos": pos,
        "key": [E.value_to_wire(v) for v in key_values],
        "row_id": row_id,
        "col_root": E.hex32(col_root),
    }


def _build_proofs(
    store, schema, n_rows, rows_out, predecessor, successor, projected_idx,
):
    known_positions = {row["pos"] for row in rows_out}
    if predecessor is not None:
        known_positions.add(predecessor["pos"])
    if successor is not None:
        known_positions.add(successor["pos"])

    # Row-tree inclusion proof: exact complement, shared paths merged.
    row_nodes = []
    if n_rows > 0:
        for level, idx in sorted(trees.complement(list(known_positions), n_rows)):
            if level == 0:
                digest = store.get_leaf(idx)[3]
            else:
                digest = store.get_row_node(level, idx)
            row_nodes.append(
                {
                    "level": level,
                    "idx": idx,
                    "digest": E.hex32(digest),
                }
            )
    row_proof = {"n": n_rows, "nodes": row_nodes}

    # Per-row column-tree proofs for the coordinate leaf and projected leaves.
    c_plus_1 = schema.column_count + 1
    open_leaves = [0] + [j + 1 for j in projected_idx]
    needed = trees.complement(open_leaves, c_plus_1)
    column_proofs: dict[str, dict] = {}
    for row in rows_out:
        pos = row["pos"]
        nodes = []
        for level, idx in sorted(needed):
            nodes.append(
                {
                    "level": level,
                    "idx": idx,
                    "digest": E.hex32(
                        store.get_col_node(pos, level, idx)
                    ),
                }
            )
        column_proofs[str(pos)] = {"open": open_leaves, "nodes": nodes}
    return row_proof, column_proofs
