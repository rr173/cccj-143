"""Independent offline page verifier.

The verifier has no database connection and no network access.  Its inputs
are exactly:

* the trusted root credential obtained out-of-band from the data center;
* the original query the client constructed;
* one page response from the distributor;
* the previously saved, already-verified continuation token (or ``None``).

It proves -- not merely that each row exists somewhere in the tree -- that
this page starts at the correct position, is internally contiguous, projects
values belonging to the correct leaf/column of the correct row, and that the
exhausted / has-successor claim is true for the bound snapshot and range.

Every structural check is exact: missing proof nodes, extra unused nodes,
duplicate/conflicting nodes, wrong lengths or ranges are all rejected.
"""

from __future__ import annotations

from . import encoding as E
from . import trees
from .query import (
    Query,
    coord_equal,
    key_equal,
    key_in_range,
    key_less,
    range_is_empty,
)
from .root import (
    parse_and_check_root,
    parse_continuation,
    read_continuation_fields,
    sign_continuation_body,
)


class VerificationError(Exception):
    pass


# ---------------------------------------------------------------------------
def verify_page(root_obj: dict, query: Query, page: dict,
                expected_continuation: dict | None = None) -> dict:
    schema, n_rows, row_root, snap_id, token_key = parse_and_check_root(
        root_obj
    )
    _check_envelope(page, snap_id, query)

    key_cols = [c for c in schema.columns if c.key]
    low, high = tuple(query.low), tuple(query.high)
    empty_range = range_is_empty(schema, query.low, query.high)

    # Anchor: either the range start or the bound continuation coordinate.
    anchor_key, anchor_rid = low, -(1 << 63)
    if expected_continuation is not None:
        c_snap, c_low, c_high, anchor_key, anchor_rid = parse_continuation(
            expected_continuation, token_key
        )
        if c_snap != snap_id:
            raise VerificationError("continuation snapshot id mismatch")
        if c_low != query.low or c_high != query.high:
            raise VerificationError(
                "continuation bound range differs from query range"
            )
    if page.get("continuation_in") != expected_continuation:
        raise VerificationError("page continuation_in does not match token")
    if expected_continuation is not None and "token_mac" not in (
        page.get("continuation_in") or {}
    ):
        raise VerificationError(
            "saved continuation credential is missing its token_mac"
        )

    start_pos = page["start_pos"]
    rows = page["rows"]
    predecessor = page.get("predecessor")
    successor = page.get("successor")
    exhausted = page["exhausted"]

    # --------------------------------------------------------------- structure
    if not isinstance(start_pos, int) or isinstance(start_pos, bool):
        raise VerificationError("bad start_pos")
    if not 0 <= start_pos <= n_rows:
        raise VerificationError("start_pos outside [0, N]")
    if not isinstance(rows, list):
        raise VerificationError("rows must be a list")
    if len(rows) > query.page_length:
        raise VerificationError("page exceeds requested page_length")
    if not isinstance(exhausted, bool):
        raise VerificationError("exhausted must be a boolean")

    projected_idx = [schema.index(name) for name in query.projection]

    # ------------------------------------------------------------- empty cases
    if empty_range or n_rows == 0:
        if rows:
            raise VerificationError("empty range/snapshot must return no rows")
        if n_rows == 0:
            if start_pos != 0 or predecessor is not None or successor is not None:
                raise VerificationError(
                    "empty snapshot must return a bare empty page"
                )
        if not isinstance(start_pos, int) or not 0 <= start_pos <= n_rows:
            raise VerificationError("bad start_pos on empty page")
        if not exhausted or page.get("next_continuation") is not None:
            raise VerificationError("empty range must be marked exhausted")
        if n_rows > 0:
            # The stubs around the located window prove the range holds no
            # row; they are authenticated against the trusted row-tree root.
            known = set()
            if predecessor is not None:
                if predecessor["pos"] != start_pos - 1:
                    raise VerificationError("predecessor position mismatch")
                known.add(predecessor["pos"])
                pk = tuple(E.value_from_wire(v) for v in predecessor["key"])
                if key_in_range(schema, pk, query.low, query.high):
                    raise VerificationError(
                        "empty-range claim hides an in-range predecessor"
                    )
            elif start_pos != 0:
                raise VerificationError("missing predecessor on empty page")
            if successor is not None:
                if successor["pos"] != start_pos:
                    raise VerificationError("successor position mismatch")
                known.add(successor["pos"])
                sk = tuple(E.value_from_wire(v) for v in successor["key"])
                if key_in_range(schema, sk, query.low, query.high):
                    raise VerificationError(
                        "empty-range claim hides an in-range successor"
                    )
            _verify_row_proof(
                page, schema, n_rows, known, predecessor, successor,
                row_root, {}
            )
        else:
            _verify_empty_tree_proof(page, row_root)
        return _ok(page, next_token=None)

    if not rows:
        _verify_empty_nonempty_range(
            page, schema, low, high, start_pos,
            predecessor, n_rows, row_root,
        )
        if not exhausted or page.get("next_continuation") is not None:
            raise VerificationError(
                "zero-row page may only be returned with an exhausted claim"
            )
        return _ok(page, next_token=None)

    # ---------------------------------------------------------- returned rows
    row_digests: dict[int, bytes] = {}
    prev_pos = start_pos - 1
    for i, row in enumerate(rows):
        pos = row.get("pos")
        if not isinstance(pos, int) or isinstance(pos, bool):
            raise VerificationError("bad row position")
        if i == 0:
            if pos != start_pos:
                raise VerificationError("first row is not at start_pos")
        elif pos != prev_pos + 1:
            raise VerificationError("page rows are not contiguous")
        prev_pos = pos

        key_values = _decode_key_wire(row, len(key_cols))
        row_id = row.get("row_id")
        if not isinstance(row_id, int) or isinstance(row_id, bool):
            raise VerificationError("bad row_id")
        if not -(1 << 63) <= row_id <= (1 << 63) - 1:
            raise VerificationError("row_id outside int64 range")
        col_root = _verify_column_proof(
            page, schema, row, pos, key_values, row_id, projected_idx,
            query.projection
        )
        digest = trees.row_leaf_digest(
            pos, list(key_values), row_id, col_root
        )
        if pos in row_digests:
            raise VerificationError("duplicate row position in page")
        row_digests[pos] = digest
        if not key_in_range(schema, key_values, query.low, query.high):
            raise VerificationError("returned row is outside [low, high)")

    # strict full-coordinate order inside the page
    for i in range(1, len(rows)):
        ka = tuple(E.value_from_wire(v) for v in rows[i - 1]["key"])
        kb = tuple(E.value_from_wire(v) for v in rows[i]["key"])
        if not (key_less(schema, ka, kb) or
                (key_equal(ka, kb) and
                 rows[i - 1]["row_id"] < rows[i]["row_id"])):
            raise VerificationError("rows not in strict coordinate order")

    first_key = tuple(E.value_from_wire(v) for v in rows[0]["key"])

    # ------------------------------------------------- start-anchor predicate
    if expected_continuation is None:
        if key_less(schema, first_key, low):
            raise VerificationError("first page starts below range low")
    else:
        # A valid continuation token names the exact existing leaf at which
        # the next page must start (the honest pager always binds it to a
        # real successor coordinate).  Requiring exact equality means a
        # forged anchor cannot make lower_bound skip over intermediate rows.
        if (not key_equal(first_key, anchor_key)
                or rows[0]["row_id"] != anchor_rid):
            raise VerificationError(
                "page does not start at the continuation anchor"
            )
    if predecessor is not None:
        pred_digest = _check_stub(
            predecessor, schema, start_pos - 1, page
        )
        row_digests[predecessor["pos"]] = pred_digest
        pred_key = tuple(E.value_from_wire(v) for v in predecessor["key"])
        pred_rid = predecessor["row_id"]
        if not _coord_less_eq(pred_key, pred_rid, first_key,
                              rows[0]["row_id"], schema):
            raise VerificationError("predecessor not before first row")
        if expected_continuation is None:
            if key_in_range(schema, pred_key, query.low, query.high):
                raise VerificationError(
                    "in-range predecessor would mean a missing row"
                )
        else:
            if not _coord_less_eq(pred_key, pred_rid,
                                  anchor_key, anchor_rid, schema):
                raise VerificationError(
                    "predecessor lies after the continuation anchor"
                )
    else:
        if start_pos != 0:
            raise VerificationError(
                "missing predecessor for start_pos > 0"
            )

    # ------------------------------------------------------------- end / more
    stop = rows[-1]["pos"] + 1
    signed_next = None
    if exhausted:
        # No in-range row may exist after the last returned row.
        if successor is not None:
            succ_key = tuple(E.value_from_wire(v) for v in successor["key"])
            if key_in_range(schema, succ_key, query.low, query.high):
                raise VerificationError(
                    "exhausted claim contradicted by in-range successor"
                )
        if page.get("next_continuation") is not None:
            raise VerificationError("exhausted page must not carry a token")
    else:
        if successor is None:
            raise VerificationError(
                "non-exhausted page must prove an immediate successor"
            )
        if successor["pos"] != stop:
            raise VerificationError("successor is not the next leaf position")
        succ_digest = _check_stub(successor, schema, stop, page)
        row_digests[successor["pos"]] = succ_digest
        succ_key = tuple(E.value_from_wire(v) for v in successor["key"])
        if not key_in_range(schema, succ_key, query.low, query.high):
            raise VerificationError(
                "successor outside range contradicts non-exhausted claim"
            )
        token_body = page.get("next_continuation")
        if not isinstance(token_body, dict):
            raise VerificationError("non-exhausted page must carry a token")
        if "token_mac" in token_body:
            raise VerificationError(
                "distributor must not supply the token MAC"
            )
        t_snap, t_low, t_high, t_key, t_rid = read_continuation_fields(
            token_body
        )
        if t_snap != snap_id or t_low != query.low or t_high != query.high:
            raise VerificationError("token binds wrong snapshot or range")
        if not coord_equal(t_key, t_rid, succ_key, successor["row_id"]):
            raise VerificationError("token does not bind the successor leaf")
        if len(rows) != query.page_length:
            raise VerificationError(
                "non-exhausted page must contain exactly page_length rows"
            )
        # The client signs the body with the secret from its trusted root;
        # this signed credential is what gets saved for the next request.
        signed_next = sign_continuation_body(token_body, token_key)

    # -------------------------------------------------- row-tree global proof
    known = set(row_digests)
    if predecessor is not None:
        known.add(predecessor["pos"])
    if successor is not None:
        known.add(successor["pos"])
    _verify_row_proof(
        page, schema, n_rows, known, predecessor, successor, row_root,
        row_digests
    )
    return _ok(page, signed_next)


# ---------------------------------------------------------------------------
def _check_envelope(page: dict, snap_id: str, query: Query) -> None:
    if not isinstance(page, dict):
        raise VerificationError("page must be an object")
    if page.get("format") != "relslice-page" or page.get("version") != 1:
        raise VerificationError("unsupported page format/version")
    if page.get("protocol_id") != E.PROTOCOL_ID.decode("ascii"):
        raise VerificationError("page protocol id mismatch")
    if page.get("snapshot_id") != snap_id:
        raise VerificationError(
            "page belongs to a different snapshot; mixing rejected"
        )
    if page.get("query") != query.to_dict():
        raise VerificationError(
            "page query envelope differs from the original query"
        )
    if not isinstance(page.get("n_rows"), int) or isinstance(
        page["n_rows"], bool
    ):
        raise VerificationError("bad n_rows in page")


def _decode_key_wire(row: dict, n_key: int) -> tuple[object, ...]:
    raw = row.get("key")
    if not isinstance(raw, list) or len(raw) != n_key:
        raise VerificationError("row key shape mismatch")
    return tuple(E.value_from_wire(v) for v in raw)


def _verify_column_proof(page, schema, row, pos, key_values, row_id,
                         projected_idx, projection_names) -> bytes:
    proofs = page.get("column_proofs")
    if not isinstance(proofs, dict) or str(pos) not in proofs:
        raise VerificationError(f"missing column proof for pos {pos}")
    proof = proofs[str(pos)]
    c_plus_1 = schema.column_count + 1
    open_leaves = [0] + [j + 1 for j in projected_idx]
    if proof.get("open") != open_leaves:
        raise VerificationError(
            "column proof open-leaf set disagrees with projection"
        )

    # Recompute the opened leaf digests.
    values_obj = row.get("values")
    if not isinstance(values_obj, dict) or set(values_obj) != set(
        projection_names
    ):
        raise VerificationError(
            "row values must contain exactly the projected columns"
        )
    known: dict[int, bytes] = {}
    known[0] = trees.col_leaf_digest(
        0, trees.coord_payload(list(key_values), row_id)
    )
    for name, col_idx in zip(projection_names, projected_idx):
        encoded = E.wire_to_encoded(values_obj[name])
        # strict type check against the schema
        schema.columns[col_idx].check_value(
            E.value_from_wire(values_obj[name])
        )
        known[col_idx + 1] = trees.col_leaf_digest(col_idx + 1, encoded)

    needed = trees.complement(open_leaves, c_plus_1)
    proof_nodes, _ = _parse_node_set(proof.get("nodes"))
    if set(proof_nodes) != needed:
        raise VerificationError(
            "column proof has missing, extra or misplaced nodes"
        )
    root = trees.evaluate("col", c_plus_1, known, proof_nodes)
    return root


def _parse_node_set(raw):
    if not isinstance(raw, list):
        raise VerificationError("proof nodes must be a list")
    out: dict[tuple[int, int], bytes] = {}
    for node in raw:
        if not isinstance(node, dict):
            raise VerificationError("proof node must be an object")
        level, idx, digest = node.get("level"), node.get("idx"), node.get(
            "digest"
        )
        if (not isinstance(level, int) or isinstance(level, bool)
                or not isinstance(idx, int) or isinstance(idx, bool)
                or level < 0 or idx < 0):
            raise VerificationError("malformed proof node coordinates")
        blob = E.from_hex32(digest)
        key = (level, idx)
        if key in out:
            raise VerificationError("duplicate/conflicting proof node")
        out[key] = blob
    return out, None


def _check_stub(stub, schema, expected_pos, page) -> bytes:
    if not isinstance(stub, dict):
        raise VerificationError("malformed boundary stub")
    if stub.get("pos") != expected_pos:
        raise VerificationError("boundary stub position mismatch")
    key_values = tuple(
        E.value_from_wire(v) for v in stub.get("key", [])
    )
    n_key = len(schema.key_names)
    if len(key_values) != n_key:
        raise VerificationError("boundary stub key shape mismatch")
    row_id = stub.get("row_id")
    if not isinstance(row_id, int) or isinstance(row_id, bool):
        raise VerificationError("boundary stub row_id mismatch")
    col_root = E.from_hex32(stub.get("col_root", ""))
    digest = trees.row_leaf_digest(
        expected_pos, list(key_values), row_id, col_root
    )
    return digest


def _verify_row_proof(page, schema, n_rows, known_positions, predecessor,
                      successor, row_root, row_digests):
    proof = page.get("row_proof")
    if not isinstance(proof, dict) or proof.get("n") != n_rows:
        raise VerificationError("row proof leaf count mismatch")
    proof_nodes, _ = _parse_node_set(proof.get("nodes"))
    if n_rows == 0:
        if proof_nodes or known_positions:
            raise VerificationError("empty tree must have an empty proof")
        if trees.empty_digest("row", 0, 0) != row_root:
            raise VerificationError("empty-snapshot root mismatch")
        return
    expected = trees.complement(list(known_positions), n_rows)
    if set(proof_nodes) != expected:
        raise VerificationError(
            "row proof has missing, extra or misplaced nodes"
        )
    known_leaves: dict[int, bytes] = dict(row_digests)
    if predecessor is not None:
        known_leaves[predecessor["pos"]] = _check_stub(
            predecessor, schema, predecessor["pos"], page
        )
    if successor is not None:
        known_leaves[successor["pos"]] = _check_stub(
            successor, schema, successor["pos"], page
        )
    if set(known_leaves) != known_positions:
        raise VerificationError("internal error: known leaf set mismatch")
    computed = trees.evaluate("row", n_rows, known_leaves, proof_nodes)
    if computed != row_root:
        raise VerificationError(
            "row-tree root mismatch; proof does not match trusted root"
        )


def _verify_empty_tree_proof(page, row_root):
    proof = page.get("row_proof")
    if not isinstance(proof, dict) or proof.get("n") != 0:
        raise VerificationError("row proof leaf count mismatch")
    if proof.get("nodes"):
        raise VerificationError("empty tree must have an empty proof")
    if trees.empty_digest("row", 0, 0) != row_root:
        raise VerificationError("empty-snapshot root mismatch")


def _verify_empty_nonempty_range(page, schema, low, high, start_pos,
                                 predecessor, n_rows, row_root):
    # A zero-row page on a nonempty range: boundary stubs adjacent to the
    # located window prove that no in-range row exists.
    if predecessor is not None:
        if predecessor["pos"] != start_pos - 1:
            raise VerificationError("predecessor position mismatch")
        pred_key = tuple(E.value_from_wire(v) for v in predecessor["key"])
        if key_in_range(schema, pred_key, list(low), list(high)):
            raise VerificationError(
                "zero-row page hides an in-range predecessor"
            )
    elif start_pos != 0:
        raise VerificationError("zero-row page missing predecessor")
    successor = page.get("successor")
    if successor is not None:
        if successor["pos"] != start_pos:
            raise VerificationError("successor position mismatch")
        succ_key = tuple(E.value_from_wire(v) for v in successor["key"])
        if key_in_range(schema, succ_key, list(low), list(high)):
            raise VerificationError(
                "zero-row page hides an in-range successor"
            )
    known = set()
    if predecessor is not None:
        known.add(predecessor["pos"])
    if successor is not None:
        known.add(successor["pos"])
    _verify_row_proof(
        page, schema, n_rows, known, predecessor, successor, row_root, {}
    )


# --------------------------------------------------------------- comparisons
def _coord_less_eq(key_a, rid_a, key_b, rid_b, schema) -> bool:
    if key_less(schema, key_a, key_b):
        return True
    if key_less(schema, key_b, key_a):
        return False
    return rid_a <= rid_b


def _ok(page, next_token):
    return {
        "valid": True,
        "snapshot_id": page["snapshot_id"],
        "rows_returned": len(page["rows"]),
        "exhausted": page["exhausted"],
        "next_continuation": next_token,
    }


def verify_root_only(root_obj: dict):
    return parse_and_check_root(root_obj)[:4]
