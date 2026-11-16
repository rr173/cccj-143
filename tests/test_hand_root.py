"""Hand-constructed tree roots, without using the builder or pager.

These tests recompute digests straight from the documented encoding and
hashing specification (see ``relslice/encoding.py`` and
``relslice/trees.py``) and compare them against what the full builder
emits.  If the builder's root ever changes without the spec changing, this
test fails -- which is exactly the independent-implementation check.
"""

import hashlib
import struct
import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import unittest  # noqa: E402

from relslice import encoding as E  # noqa: E402
from relslice import trees  # noqa: E402
from helpers import build_hand_db, make_schema  # noqa: E402


def spec_hash(domain: str, *parts: bytes) -> bytes:
    """Independent re-statement of the domain-separated hash rule."""
    h = hashlib.sha256()
    h.update(b"relslice/v1|")
    h.update(domain.encode("ascii"))
    h.update(b"|")
    for part in parts:
        h.update(struct.pack(">I", len(part)))
        h.update(part)
    return h.digest()


def spec_text(s: str) -> bytes:
    raw = s.encode("utf-8")
    return bytes([E.TAG_TEXT]) + struct.pack(">I", len(raw)) + raw


def spec_int(n: int) -> bytes:
    return bytes([E.TAG_INT]) + struct.pack(">I", 8) + struct.pack(">q", n)


def spec_coord(key_texts, row_id):
    # coord payload = lp(enc(k0)) || ... || i64(row_id)
    payload = b"".join(
        struct.pack(">I", len(spec_text(t))) + spec_text(t)
        for t in key_texts
    ) + struct.pack(">q", row_id)
    return payload


class HandBuiltRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.db, cls.schema, cls.root = build_hand_db()

    def test_single_row_leaf_digest_from_spec(self):
        # Row 0 = (a, row_id=10); business columns are k="a", v=10, so the
        # column tree has C+1 = 3 leaves: coordinate, k cell, v cell.
        coord_payload = spec_coord(["a"], 10)
        coord_leaf = spec_hash("colleaf", struct.pack(">I", 0), coord_payload)
        k_leaf = spec_hash(
            "colleaf", struct.pack(">I", 1), spec_text("a")
        )
        v_leaf = spec_hash(
            "colleaf", struct.pack(">I", 2), spec_int(10)
        )
        # level 1: (coord, k) pair and v paired with an empty slot
        empty_l0_3 = spec_hash(
            "colempty", struct.pack(">I", 0), struct.pack(">Q", 3)
        )
        node10 = spec_hash(
            "colnode", struct.pack(">I", 1), struct.pack(">Q", 0),
            coord_leaf, k_leaf,
        )
        node11 = spec_hash(
            "colnode", struct.pack(">I", 1), struct.pack(">Q", 1),
            v_leaf, empty_l0_3,
        )
        col_root = spec_hash(
            "colnode", struct.pack(">I", 2), struct.pack(">Q", 0),
            node10, node11,
        )
        prim_root, _ = trees.build_tree("col", [coord_leaf, k_leaf, v_leaf])
        self.assertEqual(col_root, prim_root)

        row_leaf = spec_hash(
            "rowleaf",
            struct.pack(">Q", 0),
            coord_payload,
            col_root,
        )
        self.assertEqual(
            row_leaf,
            trees.row_leaf_digest(0, ["a"], 10, col_root),
        )

    def test_full_row_root_rebuilt_by_hand(self):
        # Rebuild all five row leaves and the row tree root purely from the
        # spec, then compare with the builder's trusted root.
        rows = [
            (("a",), 10, "a", 10),
            (("a",), 11, "a", 11),
            (("b",), 30, "b", 30),
            (("d",), 40, "d", 40),
            (("d",), 41, "d", 41),
        ]
        leaves = []
        for pos, (key, rid, k_val, v_val) in enumerate(rows):
            coord_payload = spec_coord(list(key), rid)
            coord_leaf = spec_hash(
                "colleaf", struct.pack(">I", 0), coord_payload
            )
            k_leaf = spec_hash(
                "colleaf", struct.pack(">I", 1), spec_text(k_val)
            )
            v_leaf = spec_hash(
                "colleaf", struct.pack(">I", 2), spec_int(v_val)
            )
            empty_l0_3 = spec_hash(
                "colempty", struct.pack(">I", 0), struct.pack(">Q", 3)
            )
            node10 = spec_hash(
                "colnode", struct.pack(">I", 1), struct.pack(">Q", 0),
                coord_leaf, k_leaf,
            )
            node11 = spec_hash(
                "colnode", struct.pack(">I", 1), struct.pack(">Q", 1),
                v_leaf, empty_l0_3,
            )
            col_root = spec_hash(
                "colnode", struct.pack(">I", 2), struct.pack(">Q", 0),
                node10, node11,
            )
            leaf = spec_hash(
                "rowleaf",
                struct.pack(">Q", pos),
                coord_payload,
                col_root,
            )
            leaves.append(leaf)

        # level 1: pairs (0,1), (2,3), and 4 paired with an empty slot
        level1 = []
        for idx in range(3):
            left = leaves[2 * idx]
            if 2 * idx + 1 < 5:
                right = leaves[2 * idx + 1]
            else:
                right = spec_hash(
                    "rowempty",
                    struct.pack(">I", 0),
                    struct.pack(">Q", 5),
                )
            level1.append(
                spec_hash(
                    "rownode",
                    struct.pack(">I", 1),
                    struct.pack(">Q", idx),
                    left,
                    right,
                )
            )
        # level 2: pair (0,1), index 2 pairs with empty slot at level 1
        pair01 = spec_hash(
            "rownode",
            struct.pack(">I", 2),
            struct.pack(">Q", 0),
            level1[0],
            level1[1],
        )
        empty_l1_3 = spec_hash(
            "rowempty", struct.pack(">I", 1), struct.pack(">Q", 3)
        )
        pair2 = spec_hash(
            "rownode",
            struct.pack(">I", 2),
            struct.pack(">Q", 1),
            level1[2],
            empty_l1_3,
        )
        root = spec_hash(
            "rownode",
            struct.pack(">I", 3),
            struct.pack(">Q", 0),
            pair01,
            pair2,
        )
        self.assertEqual(root, bytes.fromhex(self.root["row_tree_root"]))

        # And the root commitment itself, rebuilt from spec pieces, including
        # the secret token_auth_key committed inside the trusted root.
        schema = make_schema()
        token_key = bytes.fromhex(self.root["token_auth_key"])
        commitment = spec_hash(
            "root",
            b"relslice/v1",
            struct.pack(">I", len(b"snap-hand")) + b"snap-hand",
            schema.canonical(),
            struct.pack(">Q", 5),
            struct.pack(">I", 2),
            root,
            token_key,
        )
        self.assertEqual(
            commitment, bytes.fromhex(self.root["root_commitment"])
        )

    def test_type_distinction_vectors(self):
        # null, "", "123", 123, true must all encode differently.
        vectors = [
            E.encode_value(None),
            E.encode_value(""),
            E.encode_value("123"),
            E.encode_value(123),
            E.encode_value(True),
        ]
        self.assertEqual(len(set(vectors)), 5)
        self.assertEqual(E.decode_value(vectors[0]), None)
        self.assertEqual(E.decode_value(vectors[1]), "")
        self.assertEqual(E.decode_value(vectors[2]), "123")
        self.assertEqual(E.decode_value(vectors[3]), 123)
        self.assertEqual(E.decode_value(vectors[4]), True)
        self.assertNotEqual(E.encode_value(True), E.encode_value(1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
