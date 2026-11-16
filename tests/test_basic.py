"""Hand-checked paging tests on the fixed a,a,b,d,d relation.

Expected contents of [a, d) (left-closed, right-open; d rows excluded):

    position 0  (a, row_id=10)  v=10
    position 1  (a, row_id=11)  v=11
    position 2  (b, row_id=30)  v=30

Every page's coordinates, projected values and exhausted flag are asserted
literally, then every page is verified by the independent offline verifier.
"""

import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import unittest  # noqa: E402

from relslice import generate_page, open_store, verify_page  # noqa: E402
from helpers import (  # noqa: E402
    HAND_COORDS,
    build_hand_db,
    drain,
    make_range,
    make_schema,
)


def coords_of(page):
    return [
        (tuple(v["v"] for v in row["key"]), row["row_id"])
        for row in page["rows"]
    ]


def values_of(page):
    return [row["values"] for row in page["rows"]]


class HandWrittenPagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.db, cls.schema, cls.root = build_hand_db()
        cls.store = open_store(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_full_relation_order_and_duplicates(self):
        # Whole-relation ordering, including both d rows and duplicate a's.
        q = make_range("a", "e", page_length=10)
        pages = drain(self.store, self.root, q)
        self.assertEqual(len(pages), 1)
        page = pages[0]
        self.assertTrue(page["exhausted"])
        self.assertEqual(coords_of(page), HAND_COORDS)

    def test_range_a_d_excludes_d(self):
        q = make_range("a", "d", page_length=10)
        page = generate_page(self.store, q)
        self.assertEqual(
            coords_of(page),
            [(("a",), 10), (("a",), 11), (("b",), 30)],
        )
        self.assertTrue(page["exhausted"])
        verify_page(self.root, q, page)

    def test_page_length_one(self):
        q = make_range("a", "d", page_length=1)
        pages = drain(self.store, self.root, q)
        self.assertEqual(len(pages), 3)
        expected = [
            ([(("a",), 10)], False),
            ([(("a",), 11)], False),
            ([(("b",), 30)], True),
        ]
        for page, (exp_coords, exp_exhausted) in zip(pages, expected):
            self.assertEqual(coords_of(page), exp_coords)
            self.assertEqual(page["exhausted"], exp_exhausted)
        # same business key must survive across the page boundary
        self.assertEqual(pages[0]["rows"][0]["key"], pages[1]["rows"][0]["key"])

    def test_page_length_two(self):
        q = make_range("a", "d", page_length=2)
        pages = drain(self.store, self.root, q)
        self.assertEqual(len(pages), 2)
        self.assertEqual(
            coords_of(pages[0]), [(("a",), 10), (("a",), 11)]
        )
        self.assertFalse(pages[0]["exhausted"])
        self.assertEqual(coords_of(pages[1]), [(("b",), 30)])
        self.assertTrue(pages[1]["exhausted"])

    def test_page_length_three_hits_boundary(self):
        # L=3 equals the range size exactly: one full page, exhausted.
        q = make_range("a", "d", page_length=3)
        pages = drain(self.store, self.root, q)
        self.assertEqual(len(pages), 1)
        self.assertEqual(
            coords_of(pages[0]),
            [(("a",), 10), (("a",), 11), (("b",), 30)],
        )
        self.assertTrue(pages[0]["exhausted"])

    def test_projected_values_literal(self):
        q = make_range("a", "d", page_length=2)
        page = generate_page(self.store, q)
        self.assertEqual(
            values_of(page),
            [
                {"k": {"t": "text", "v": "a"}, "v": {"t": "int64", "v": 10}},
                {"k": {"t": "text", "v": "a"}, "v": {"t": "int64", "v": 11}},
            ],
        )

    def test_projection_and_length_change_keeps_suffix(self):
        # Start with narrow projection/L=1, then switch projection and length
        # while continuing: no row may be skipped.
        q1 = make_range("a", "d", projection=("v",), page_length=1)
        p1 = generate_page(self.store, q1)
        r1 = verify_page(self.root, q1, p1)
        token = r1["next_continuation"]

        q2 = make_range("a", "d", projection=("k",), page_length=5)
        p2 = generate_page(self.store, q2, token)
        verify_page(self.root, q2, p2, token)
        self.assertTrue(p2["exhausted"])
        # suffix must be exactly the two rows after (a,10)
        self.assertEqual(
            coords_of(p2), [(("a",), 11), (("b",), 30)]
        )
        # v must not appear in a page that only projected k
        for row in p2["rows"]:
            self.assertEqual(set(row["values"]), {"k"})

    def test_continuation_inside_same_key_group(self):
        # Anchor lands between the two a rows.  The token names the exact
        # first coordinate of the next page, so it binds (a, 11).
        from relslice.encoding import from_hex32
        from relslice.root import make_continuation

        token = make_continuation(
            from_hex32(self.root["token_auth_key"]),
            "snap-hand",
            ["a"],
            ["d"],
            ("a",),
            11,
        )
        q = make_range("a", "d", page_length=10)
        page = generate_page(self.store, q, token)
        verify_page(self.root, q, page, token)
        self.assertEqual(
            coords_of(page), [(("a",), 11), (("b",), 30)]
        )
        self.assertTrue(page["exhausted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
