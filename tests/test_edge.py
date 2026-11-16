"""Edge cases, typed encoding and bad-input rejection tests."""

import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import os  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402

from relslice import (  # noqa: E402
    BuildError,
    Query,
    Schema,
    build_snapshot,
    encoding as E,
    generate_page,
    open_store,
    verify_page,
)
from relslice.encoding import EncodingError  # noqa: E402
from relslice.verifier import VerificationError  # noqa: E402
from helpers import drain, expect_reject, mutate  # noqa: E402


def typed(v):
    return E.value_to_wire(v)


class EdgeCaseTests(unittest.TestCase):
    def test_empty_snapshot(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "empty.db")
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "int64", "key": True},
                    {"name": "note", "type": "text", "key": False},
                ],
                "row_id_name": "row_id",
            }
        )
        root = build_snapshot(db, schema, iter([]), snapshot_id="snap-empty")
        self.assertEqual(root["n_rows"], 0)
        store = open_store(db)
        q = Query.from_dict(
            {
                "low": [typed(0)],
                "high": [typed(100)],
                "projection": ["note"],
                "page_length": 4,
            },
            schema,
        )
        page = generate_page(store, q)
        self.assertEqual(page["rows"], [])
        self.assertTrue(page["exhausted"])
        self.assertEqual(page["row_proof"]["nodes"], [])
        result = verify_page(root, q, page)
        self.assertTrue(result["valid"])
        store.close()

    def test_empty_range_nonempty_snapshot(self):
        from helpers import build_hand_db

        _, db, schema, root = build_hand_db()
        store = open_store(db)
        # low == high and low > high are both legal empty ranges
        for low, high in (("c", "c"), ("z", "a")):
            q = Query.from_dict(
                {
                    "low": [typed(low)],
                    "high": [typed(high)],
                    "projection": ["k"],
                    "page_length": 3,
                },
                schema,
            )
            page = generate_page(store, q)
            self.assertEqual(page["rows"], [])
            self.assertTrue(page["exhausted"])
            verify_page(root, q, page)
        store.close()

    def test_range_with_no_matching_rows(self):
        from helpers import build_hand_db

        _, db, schema, root = build_hand_db()
        store = open_store(db)
        # Range between existing keys that contains no row: [c, d)
        q = Query.from_dict(
            {
                "low": [typed("c")],
                "high": [typed("d")],
                "projection": ["k"],
                "page_length": 2,
            },
            schema,
        )
        page = generate_page(store, q)
        self.assertEqual(page["rows"], [])
        self.assertTrue(page["exhausted"])
        verify_page(root, q, page)
        store.close()

    def test_oversized_text_roundtrip(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "big.db")
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "text", "key": True},
                    {"name": "blob", "type": "text", "key": False},
                ],
                "row_id_name": "row_id",
            }
        )
        big = "界" * 50_000  # multi-byte Unicode, well over one page
        rows = [
            {"k": "x", "blob": big, "row_id": 1},
            {"k": "y", "blob": "", "row_id": 2},
        ]
        root = build_snapshot(db, schema, iter(rows), snapshot_id="snap-big")
        store = open_store(db)
        q = Query.from_dict(
            {
                "low": [typed("x")],
                "high": [typed("z")],
                "projection": ["blob"],
                "page_length": 1,
            },
            schema,
        )
        pages = drain(store, root, q)
        self.assertEqual(pages[0]["rows"][0]["values"]["blob"]["v"], big)
        self.assertEqual(pages[1]["rows"][0]["values"]["blob"]["v"], "")
        # only the projected column is present in the payload
        self.assertEqual(set(pages[0]["rows"][0]["values"]), {"blob"})
        store.close()

    def test_all_null_projected_column(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "nulls.db")
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "int64", "key": True},
                    {"name": "maybe", "type": "bool", "key": False},
                ],
                "row_id_name": "row_id",
            }
        )
        rows = [
            {"k": 1, "maybe": None, "row_id": 1},
            {"k": 2, "maybe": None, "row_id": 2},
        ]
        root = build_snapshot(db, schema, iter(rows), snapshot_id="snap-null")
        store = open_store(db)
        q = Query.from_dict(
            {
                "low": [typed(0)],
                "high": [typed(10)],
                "projection": ["maybe"],
                "page_length": 5,
            },
            schema,
        )
        page = generate_page(store, q)
        for row in page["rows"]:
            self.assertEqual(row["values"]["maybe"], {"t": "null"})
        verify_page(root, q, page)
        store.close()

    def test_null_rejected_in_key_column(self):
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "text", "key": True},
                ],
                "row_id_name": "row_id",
            }
        )
        tmp = tempfile.mkdtemp()
        with self.assertRaises((EncodingError, BuildError)):
            build_snapshot(
                os.path.join(tmp, "x.db"),
                schema,
                iter([{"k": None, "row_id": 1}]),
            )

    def test_duplicate_row_id_rejected(self):
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "text", "key": True},
                ],
                "row_id_name": "row_id",
            }
        )
        tmp = tempfile.mkdtemp()
        with self.assertRaises(BuildError):
            build_snapshot(
                os.path.join(tmp, "x.db"),
                schema,
                iter([
                    {"k": "a", "row_id": 7},
                    {"k": "b", "row_id": 7},
                ]),
            )

    def test_row_id_int64_bounds_enforced(self):
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "int64", "key": True},
                ],
                "row_id_name": "row_id",
            }
        )
        tmp = tempfile.mkdtemp()
        for bad_rid in ((1 << 63), -(1 << 63) - 1):
            with self.assertRaises((EncodingError, BuildError)):
                build_snapshot(
                    os.path.join(tmp, f"{bad_rid}.db"),
                    schema,
                    iter([{"k": 1, "row_id": bad_rid}]),
                )
        # Both int64 boundary row_ids are accepted.
        db = os.path.join(tmp, "bounds.db")
        root = build_snapshot(
            db,
            schema,
            iter([
                {"k": 1, "row_id": -(1 << 63)},
                {"k": 2, "row_id": (1 << 63) - 1},
            ]),
            snapshot_id="snap-bounds",
        )
        self.assertEqual(root["n_rows"], 2)

    def test_duplicate_full_business_rows_kept(self):
        # Identical business content with distinct row_ids must both remain.
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "text", "key": True},
                    {"name": "v", "type": "int64", "key": False},
                ],
                "row_id_name": "row_id",
            }
        )
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "dup.db")
        rows = [
            {"k": "same", "v": 5, "row_id": 100},
            {"k": "same", "v": 5, "row_id": 101},
        ]
        root = build_snapshot(db, schema, iter(rows), snapshot_id="snap-dup")
        self.assertEqual(root["n_rows"], 2)
        store = open_store(db)
        q = Query.from_dict(
            {
                "low": [typed("a")],
                "high": [typed("z")],
                "projection": ["v"],
                "page_length": 10,
            },
            schema,
        )
        page = generate_page(store, q)
        self.assertEqual([r["row_id"] for r in page["rows"]], [100, 101])
        verify_page(root, q, page)
        store.close()

    def test_bad_inputs_rejected(self):
        # int64 overflow
        with self.assertRaises(EncodingError):
            E.encode_value(1 << 63)
        with self.assertRaises(EncodingError):
            E.encode_value(-(1 << 63) - 1)
        # unsupported Python type
        with self.assertRaises(EncodingError):
            E.encode_value(1.5)
        with self.assertRaises(EncodingError):
            E.encode_value(b"bytes")
        # malformed wire values
        with self.assertRaises(EncodingError):
            E.value_from_wire({"t": "int64", "v": True})
        with self.assertRaises(EncodingError):
            E.value_from_wire({"t": "int64", "v": "12"})
        with self.assertRaises(EncodingError):
            E.value_from_wire({"t": "weird"})
        with self.assertRaises(EncodingError):
            E.from_hex32("abc")
        # bool and int never collide
        self.assertNotEqual(E.encode_value(True), E.encode_value(1))
        self.assertNotEqual(E.encode_value(False), E.encode_value(0))

    def test_schema_validation(self):
        # key columns must form a prefix
        with self.assertRaises(EncodingError):
            Schema.from_dict(
                {
                    "columns": [
                        {"name": "a", "type": "text", "key": False},
                        {"name": "k", "type": "text", "key": True},
                    ],
                    "row_id_name": "row_id",
                }
            )
        # no key columns
        with self.assertRaises(EncodingError):
            Schema.from_dict(
                {
                    "columns": [
                        {"name": "a", "type": "text", "key": False},
                    ],
                    "row_id_name": "row_id",
                }
            )
        # unknown type and duplicate names
        with self.assertRaises(EncodingError):
            Schema.from_dict(
                {
                    "columns": [
                        {"name": "k", "type": "float", "key": True},
                    ],
                    "row_id_name": "row_id",
                }
            )
        with self.assertRaises(EncodingError):
            Schema.from_dict(
                {
                    "columns": [
                        {"name": "k", "type": "text", "key": True},
                        {"name": "k", "type": "int64", "key": False},
                    ],
                    "row_id_name": "row_id",
                }
            )

    def test_query_validation(self):
        from helpers import make_schema

        schema = make_schema()
        base = {
            "low": [typed("a")],
            "high": [typed("d")],
            "projection": ["k"],
            "page_length": 2,
        }
        for bad in (
            {"page_length": 0},
            {"page_length": -1},
            {"page_length": True},
            {"projection": []},
            {"projection": ["nope"]},
            {"low": []},
        ):
            obj = mutate(base)
            obj.update(bad)
            with self.assertRaises(EncodingError):
                Query.from_dict(obj, schema)

    def test_unicode_code_point_order(self):
        # Code-point order: ASCII uppercase before lowercase before CJK.
        schema = Schema.from_dict(
            {
                "columns": [
                    {"name": "k", "type": "text", "key": True},
                ],
                "row_id_name": "row_id",
            }
        )
        words = ["界", "a", "B", "aa", "A", "abc", ""]
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "u.db")
        rows = [{"k": w, "row_id": i + 1} for i, w in enumerate(words)]
        root = build_snapshot(db, schema, iter(rows), snapshot_id="snap-u")
        store = open_store(db)
        q = Query.from_dict(
            {
                "low": [typed("")],
                "high": [typed("￿")],
                "projection": ["k"],
                "page_length": 100,
            },
            schema,
        )
        page = generate_page(store, q)
        got = [r["values"]["k"]["v"] for r in page["rows"]]
        self.assertEqual(got, sorted(words))
        verify_page(root, q, page)
        store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
