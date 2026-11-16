"""Malformed-proof fuzzing: structurally invalid responses must fail closed."""

import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import unittest  # noqa: E402

from relslice import generate_page, open_store  # noqa: E402
from helpers import (  # noqa: E402
    build_hand_db,
    expect_reject,
    make_range,
    mutate,
)


class MalformedProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.db, cls.schema, cls.root = build_hand_db()
        cls.store = open_store(cls.db)
        cls.q = make_range("a", "d", page_length=2)
        cls.page = generate_page(cls.store, cls.q)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def _reject(self, page):
        expect_reject(self.root, self.q, page)

    def test_bad_digest_hex(self):
        evil = mutate(self.page)
        evil["row_proof"]["nodes"][0]["digest"] = "not-hex"
        self._reject(evil)

    def test_digest_wrong_length(self):
        evil = mutate(self.page)
        evil["row_proof"]["nodes"][0]["digest"] = "ab" * 16
        self._reject(evil)

    def test_negative_node_coordinates(self):
        evil = mutate(self.page)
        evil["row_proof"]["nodes"][0]["level"] = -1
        self._reject(evil)

    def test_non_integer_coordinates(self):
        evil = mutate(self.page)
        evil["row_proof"]["nodes"][0]["idx"] = "1"
        self._reject(evil)

    def test_nodes_not_a_list(self):
        evil = mutate(self.page)
        evil["row_proof"]["nodes"] = {"x": 1}
        self._reject(evil)

    def test_proof_leaf_count_mismatch(self):
        evil = mutate(self.page)
        evil["row_proof"]["n"] = self.page["row_proof"]["n"] + 1
        self._reject(evil)

    def test_column_proof_open_set_mismatch(self):
        evil = mutate(self.page)
        pos = str(evil["rows"][0]["pos"])
        evil["column_proofs"][pos]["open"] = [0]
        self._reject(evil)

    def test_missing_column_proof(self):
        evil = mutate(self.page)
        pos = str(evil["rows"][0]["pos"])
        del evil["column_proofs"][pos]
        self._reject(evil)

    def test_column_proof_duplicate_node(self):
        qv = make_range("a", "d", projection=("v",), page_length=1)
        page = generate_page(self.store, qv)
        evil = mutate(page)
        pos = str(evil["rows"][0]["pos"])
        evil["column_proofs"][pos]["nodes"].append(
            mutate(evil["column_proofs"][pos]["nodes"][0])
        )
        expect_reject(self.root, qv, evil)

    def test_rows_not_a_list(self):
        evil = mutate(self.page)
        evil["rows"] = {}
        self._reject(evil)

    def test_bad_page_format(self):
        evil = mutate(self.page)
        evil["format"] = "something-else"
        self._reject(evil)

    def test_foreign_protocol_id(self):
        evil = mutate(self.page)
        evil["protocol_id"] = "relslice/v9"
        self._reject(evil)

    def test_bad_typed_value_wire(self):
        evil = mutate(self.page)
        evil["rows"][0]["values"]["v"] = {"t": "int64", "v": "12"}
        self._reject(evil)

    def test_negative_position(self):
        evil = mutate(self.page)
        evil["start_pos"] = -1
        self._reject(evil)

    def test_position_beyond_n(self):
        evil = mutate(self.page)
        evil["start_pos"] = self.page["n_rows"] + 10
        self._reject(evil)


if __name__ == "__main__":
    unittest.main(verbosity=2)
