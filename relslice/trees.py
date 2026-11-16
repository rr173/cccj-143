"""Merkle tree conventions shared by the column trees and the row tree.

Two kinds of authenticated binary trees are used.

1. **Column tree** -- one per row, with ``C+1`` leaves:
   leaf 0 commits the full coordinate (business key + row_id) and leaves
   ``1..C`` commit the cell values in schema order.  A projection only opens
   leaf 0 and the projected cell leaves; every other leaf is revealed only
   through its inclusion proof, never as plaintext.

2. **Row tree** -- one per snapshot, with one leaf per row in full-coordinate
   order.  Each row leaf commits the coordinate together with that row's
   column-tree root, so column values are bound to their exact position.

Node identity is positional: ``(level, index)`` where level 0 holds leaves
and each higher level halves the count (ceil division).  Every digest is
domain separated by an ASCII tag and binds its level and index, so a node
cannot be replayed at another position or confused across tree kinds.
Missing right children are deterministic *empty* digests bound to their own
position -- there is no padding row/padding cell carrying ambiguous data.

Tags::

    colleaf  : column-tree leaf        hash parts: index, payload
    colnode  : column-tree internal    hash parts: level, index, left, right
    colempty : column-tree empty slot  hash parts: level, index
    rowleaf  : row-tree leaf           hash parts: position, coord, colroot
    rownode  : row-tree internal       hash parts: level, index, left, right
    rowempty : row-tree empty slot     hash parts: level, index
"""

from __future__ import annotations

from . import encoding as E

# Tree node count per level: level 0 has n leaves, level h = ceil(prev / 2).
def level_count(n: int, level: int) -> int:
    c = n
    for _ in range(level):
        c = (c + 1) // 2
    return c


def root_level(n: int) -> int:
    if n <= 1:
        return 0
    h = 0
    c = n
    while c > 1:
        c = (c + 1) // 2
        h += 1
    return h


def complement(positions: list[int], n: int) -> set[tuple[int, int]]:
    """Minimal set of real sibling nodes authenticating ``positions``.

    Returns ``(level, index)`` pairs for every non-empty sibling that an
    evaluator needs; empty slots are recomputed from the position and are
    therefore intentionally absent.  Nodes derivable from already-known
    subtrees are never included, which keeps the set minimal.
    """
    if n == 0:
        if positions:
            raise ValueError("positions in empty tree")
        return set()
    cur = set(positions)
    if any(not 0 <= p < n for p in cur):
        raise ValueError("leaf position out of range")
    out: set[tuple[int, int]] = set()
    level = 0
    count = n
    while count > 1:
        for i in cur:
            sib = i ^ 1
            if sib < count and sib not in cur:
                out.add((level, sib))
        cur = {i // 2 for i in cur}
        count = (count + 1) // 2
        level += 1
    return out


def empty_digest(kind: str, level: int, index: int) -> bytes:
    domain = "colempty" if kind == "col" else "rowempty"
    return E.tagged_hash(domain, E.u32(level), E.u64(index))


def internal_digest(
    kind: str, level: int, index: int, left: bytes, right: bytes
) -> bytes:
    domain = "colnode" if kind == "col" else "rownode"
    return E.tagged_hash(domain, E.u32(level), E.u64(index), left, right)


# ---------------------------------------------------------------------------
# Column tree
# ---------------------------------------------------------------------------

def coord_payload(key_values: list[object], row_id: int) -> bytes:
    parts = [E.lp(E.encode_value(k)) for k in key_values]
    parts.append(E.i64(row_id))
    return b"".join(parts)


def col_leaf_digest(index: int, payload: bytes) -> bytes:
    """Digest of column-tree leaf ``index`` (0 = coordinate leaf)."""
    return E.tagged_hash("colleaf", E.u32(index), payload)


def coord_leaf_digest(key_values: list[object], row_id: int) -> bytes:
    return col_leaf_digest(0, coord_payload(key_values, row_id))


def cell_leaf_digest(column_index: int, value: object) -> bytes:
    # column_index is 0-based over business columns; tree leaf is index+1.
    return col_leaf_digest(column_index + 1, E.encode_value(value))


def build_tree(
    kind: str, leaf_digests: list[bytes]
) -> tuple[bytes, dict[tuple[int, int], bytes]]:
    """Build a complete positional binary tree bottom up.

    Returns the root digest and every node digest (including leaves), keyed
    by ``(level, index)``.  Odd levels pair the last node with a
    position-bound empty digest.
    """
    n = len(leaf_digests)
    if n == 0:
        raise ValueError("cannot build a tree with zero leaves")
    nodes: dict[tuple[int, int], bytes] = {}
    level_digests = leaf_digests
    for idx, digest in enumerate(level_digests):
        nodes[(0, idx)] = digest
    level = 0
    count = n
    while count > 1:
        nxt: list[bytes] = []
        for idx in range((count + 1) // 2):
            left_pos = 2 * idx
            right_pos = 2 * idx + 1
            left = level_digests[left_pos]
            if right_pos < count:
                right = level_digests[right_pos]
            else:
                right = empty_digest(kind, level, right_pos)
            digest = internal_digest(kind, level + 1, idx, left, right)
            nxt.append(digest)
            nodes[(level + 1, idx)] = digest
        level_digests = nxt
        count = len(nxt)
        level += 1
    return level_digests[0], nodes


def build_column_tree(
    key_values: list[object], row_id: int, cell_values: list[object]
) -> tuple[bytes, dict[tuple[int, int], bytes]]:
    leaves = [coord_leaf_digest(key_values, row_id)]
    leaves.extend(
        cell_leaf_digest(j, value) for j, value in enumerate(cell_values)
    )
    return build_tree("col", leaves)


def row_leaf_digest(
    position: int, key_values: list[object], row_id: int, col_root: bytes
) -> bytes:
    return E.tagged_hash(
        "rowleaf",
        E.u64(position),
        coord_payload(key_values, row_id),
        col_root,
    )


def evaluate(
    kind: str,
    n: int,
    known: dict[tuple[int, int], bytes],
    proof_nodes: dict[tuple[int, int], bytes],
) -> bytes:
    """Recompute a tree root from known leaves and supplied sibling nodes.

    ``known`` maps level-0 positions to leaf digests.  Every required sibling
    must be present in ``proof_nodes``; extra or conflicting nodes are the
    caller's responsibility to reject (the verifier checks the exact
    complement set before calling this).
    """
    if n == 0:
        raise ValueError("cannot evaluate empty tree")
    cur: dict[int, bytes] = dict(known)
    count = n
    level = 0
    while count > 1:
        # Siblings supplied by the proof become nodes at this level.
        for (lvl, idx), digest in proof_nodes.items():
            if lvl == level and idx < count:
                cur.setdefault(idx, digest)
        nxt: dict[int, bytes] = {}
        needed_parents = {idx // 2 for idx in cur}
        for idx in sorted(needed_parents):
            left_pos = 2 * idx
            right_pos = 2 * idx + 1
            if left_pos not in cur:
                raise ValueError(f"missing node level={level} idx={left_pos}")
            left = cur[left_pos]
            if right_pos < count:
                if (level, right_pos) in proof_nodes:
                    right = proof_nodes[(level, right_pos)]
                elif right_pos in cur:
                    right = cur[right_pos]
                else:
                    raise ValueError(
                        f"missing node level={level} idx={right_pos}"
                    )
            else:
                right = empty_digest(kind, level, right_pos)
            nxt[idx] = internal_digest(kind, level + 1, idx, left, right)
        cur = nxt
        count = (count + 1) // 2
        level += 1
    return cur[0]
