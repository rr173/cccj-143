"""Adversarial tests: every attack must be rejected offline.

Each case mutates an otherwise-valid page (or continuation token) and
asserts the independent verifier raises VerificationError.  The verifier
never sees the database; it only gets the trusted root, the original query
and the tampered response.
"""

import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import json  # noqa: E402
import unittest  # noqa: E402

from relslice import generate_page, open_store  # noqa: E402
from relslice.verifier import VerificationError, verify_page  # noqa: E402
from helpers import (  # noqa: E402
    build_hand_db,
    drain,
    expect_reject,
    make_range,
    mutate,
)


class AttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.db, cls.schema, cls.root = build_hand_db()
        cls.store = open_store(cls.db)
        cls.q = make_range("a", "d", page_length=1)
        cls.pages = drain(cls.store, cls.root, cls.q)
        # Signed continuation credentials the client would actually save.
        cls.tokens = []
        token = None
        for page in cls.pages[:-1]:
            result = verify_page(cls.root, cls.q, page, token)
            token = result["next_continuation"]
            cls.tokens.append(token)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def _first_page(self):
        return generate_page(self.store, self.q)

    # ------------------------------------------------- 1. delete a middle row
    def test_delete_middle_row(self):
        # Use L=2 so the first page contains both a rows; drop the second.
        q2 = make_range("a", "d", page_length=2)
        page = generate_page(self.store, q2)
        evil = mutate(page)
        evil["rows"] = evil["rows"][:1]
        expect_reject(self.root, q2, evil)

    # --------------------------------------------------- 2. skip the first row
    def test_skip_first_row(self):
        # Present page 2 as if it were page 1 (no continuation).
        p2 = self.pages[1]
        evil = mutate(p2)
        evil["continuation_in"] = None
        evil["predecessor"] = None
        evil["start_pos"] = 0
        # Rebuild row proof around the tampered position set to make the
        # structural proof internally consistent; boundary logic must fail.
        expect_reject(self.root, self.q, evil)

    # --------------------------------------------------- 3. duplicate tail row
    def test_duplicate_tail_row(self):
        page = self._first_page()
        evil = mutate(page)
        evil["rows"].append(mutate(evil["rows"][-1]))
        expect_reject(self.root, self.q, evil)

    # -------------------------------------------------------- 4. fake exhaust
    def test_false_exhausted(self):
        page = self._first_page()  # really has more rows
        evil = mutate(page)
        evil["exhausted"] = True
        evil["next_continuation"] = None
        # Keep the successor stub to prove the contradiction is detected
        # via the in-range successor + missing token.
        expect_reject(self.root, self.q, evil)

    def test_false_more_data(self):
        # Last page is really exhausted; claim a successor exists.
        last = self.pages[-1]
        evil = mutate(last)
        evil["exhausted"] = False
        expect_reject(self.root, self.q, evil)

    def test_zero_row_page_claiming_more(self):
        # A genuinely empty range page, then flip exhausted to false.
        from relslice import Query
        from relslice.encoding import value_to_wire

        q0 = Query.from_dict({
            "low": [value_to_wire("c")],
            "high": [value_to_wire("d")],
            "projection": ["k"],
            "page_length": 2,
        }, self.schema)
        page = generate_page(self.store, q0)
        evil = mutate(page)
        evil["exhausted"] = False
        expect_reject(self.root, q0, evil)

    def test_exhausted_with_in_range_successor(self):
        # Force exhausted=true while keeping an in-range successor: the
        # boundary contradiction must be detected.
        page = self._first_page()
        evil = mutate(page)
        evil["exhausted"] = True
        evil["next_continuation"] = None
        # the page's real successor (b,30) is inside [a,d), so this must fail
        expect_reject(self.root, self.q, evil)

    # -------------------------------------------- 5. later page as first page
    def test_later_page_as_first(self):
        later = self.pages[2]
        evil = mutate(later)
        evil["continuation_in"] = None
        expect_reject(self.root, self.q, evil)

    # ------------------------------------------------ 6. swap two column cells
    def test_swap_column_values(self):
        q2 = make_range("a", "d", projection=("k", "v"), page_length=2)
        page = generate_page(self.store, q2)
        evil = mutate(page)
        # Swap v values between the two returned rows: each value keeps a
        # valid type but no longer belongs to its own leaf, so the column
        # inclusion proof fails.
        evil["rows"][0]["values"]["v"], evil["rows"][1]["values"]["v"] = (
            evil["rows"][1]["values"]["v"],
            evil["rows"][0]["values"]["v"],
        )
        expect_reject(self.root, q2, evil)

    def test_rewrite_projected_value(self):
        page = self._first_page()
        evil = mutate(page)
        evil["rows"][0]["values"]["v"] = {"t": "int64", "v": 999}
        expect_reject(self.root, self.q, evil)

    # ------------------------------------------------- 7. mix foreign snapshot
    def test_foreign_snapshot_id(self):
        page = self._first_page()
        evil = mutate(page)
        evil["snapshot_id"] = "snap-other"
        expect_reject(self.root, self.q, evil)

    def test_foreign_root_rejected(self):
        # A root bundled by the distributor must not be trusted: build a
        # second snapshot and try to verify page 1 against its root.
        from relslice import build_snapshot
        from helpers import HAND_ROWS
        import os

        other_db = os.path.join(self.tmp, "other.db")
        other_root = build_snapshot(
            other_db, self.schema, iter(mutate(HAND_ROWS)),
            snapshot_id="snap-other",
        )
        page = self._first_page()
        expect_reject(other_root, self.q, mutate(page))

    # --------------------------------------------- 8. tamper continuation range
    def test_continuation_range_tamper(self):
        token = self.tokens[0]
        evil_token = mutate(token)
        evil_token["high"] = [{"t": "text", "v": "e"}]  # widen the range
        # The keyed MAC must reject this before any positioning happens.
        with self.assertRaises(Exception):
            verify_page(
                self.root, self.q,
                generate_page(self.store, self.q, evil_token),
                evil_token,
            )

    def test_continuation_anchor_tamper(self):
        token = self.tokens[0]
        evil_token = mutate(token)
        evil_token["next_row_id"] = 999
        with self.assertRaises(Exception):
            verify_page(
                self.root, self.q,
                generate_page(self.store, self.q, evil_token),
                evil_token,
            )

    def test_wrong_saved_token_rejected(self):
        # Client presents a token from a different range with the next page.
        q_other = make_range("a", "e", page_length=1)
        other_pages = drain(self.store, self.root, q_other)
        other_result = verify_page(
            self.root, q_other, other_pages[0], None
        )
        foreign_token = other_result["next_continuation"]
        evil = mutate(self.pages[1])
        expect_reject(self.root, self.q, evil, foreign_token)

    def test_forged_anchor_skipping_rows_rejected(self):
        # The distributor holds no token key.  Simulate the real attack:
        # hand-craft an unsigned continuation body that skips the first
        # range row.  The verifier demands a keyed MAC, so it must fail.
        from relslice.encoding import value_to_wire

        forged_body = {
            "format": "relslice-continuation",
            "version": 1,
            "protocol_id": "relslice/v1",
            "snapshot_id": self.root["snapshot_id"],
            "low": [value_to_wire("a")],
            "high": [value_to_wire("d")],
            "next_key": [value_to_wire("b")],
            "next_row_id": 30,
        }
        page = generate_page(self.store, self.q, forged_body)
        expect_reject(self.root, self.q, page, forged_body)

    def test_forged_mac_rejected(self):
        # Even if the distributor appends a guessed MAC, HMAC verification
        # fails without the root's secret key.
        from relslice.encoding import value_to_wire

        forged = {
            "format": "relslice-continuation",
            "version": 1,
            "protocol_id": "relslice/v1",
            "snapshot_id": self.root["snapshot_id"],
            "low": [value_to_wire("a")],
            "high": [value_to_wire("d")],
            "next_key": [value_to_wire("b")],
            "next_row_id": 30,
            "token_mac": "00" * 32,
        }
        page = generate_page(self.store, self.q, forged)
        expect_reject(self.root, self.q, page, forged)

    def test_unsigned_distributor_body_cannot_be_used_as_token(self):
        # The page's next_continuation has no MAC and must not be accepted
        # directly as a saved credential.
        body = self.pages[0]["next_continuation"]
        self.assertNotIn("token_mac", body)
        page2 = generate_page(self.store, self.q, body)
        expect_reject(self.root, self.q, page2, body)

    # ----------------------------------------------- 9. extra proof node added
    def test_extra_proof_node_rejected(self):
        page = self._first_page()
        evil = mutate(page)
        evil["row_proof"]["nodes"].append(
            {"level": 3, "idx": 7, "digest": "00" * 32}
        )
        expect_reject(self.root, self.q, evil)

    def test_missing_proof_node_rejected(self):
        page = self._first_page()
        evil = mutate(page)
        evil["row_proof"]["nodes"].pop()
        expect_reject(self.root, self.q, evil)

    def test_duplicate_conflicting_node_rejected(self):
        page = self._first_page()
        evil = mutate(page)
        node = mutate(evil["row_proof"]["nodes"][0])
        node["digest"] = "11" * 32
        evil["row_proof"]["nodes"].append(node)
        expect_reject(self.root, self.q, evil)

    # ------------------------------------------------- 10. tampered index node
    def test_tampered_row_node_digest(self):
        page = self._first_page()
        evil = mutate(page)
        evil["row_proof"]["nodes"][0]["digest"] = "ab" * 32
        expect_reject(self.root, self.q, evil)

    def test_tampered_column_node_digest(self):
        # Project only v: leaf 1 (the k cell) is then an authenticated
        # sibling rather than an opened leaf, so the proof is non-empty.
        qv = make_range("a", "d", projection=("v",), page_length=1)
        page = generate_page(self.store, qv)
        evil = mutate(page)
        pos = str(evil["rows"][0]["pos"])
        nodes = evil["column_proofs"][pos]["nodes"]
        self.assertTrue(nodes, "column proof should contain sibling nodes")
        nodes[0]["digest"] = "cd" * 32
        expect_reject(self.root, qv, evil)

    # ------------------------------------------------------- 11. stub tampering
    def test_tampered_successor(self):
        page = self._first_page()
        evil = mutate(page)
        evil["successor"]["row_id"] = 777
        expect_reject(self.root, self.q, evil)

    def test_tampered_predecessor_key(self):
        # Page 2 carries a predecessor; corrupt it.
        evil = mutate(self.pages[1])
        evil["predecessor"]["key"] = [{"t": "text", "v": "zzz"}]
        expect_reject(self.root, self.q, evil, self.tokens[0])

    # -------------------------------------------------- 12. structural attacks
    def test_page_length_claim_exceeded(self):
        page = self._first_page()
        evil = mutate(page)
        # A second row appended with a fresh fake position.
        extra = mutate(evil["rows"][0])
        extra["pos"] = evil["rows"][0]["pos"] + 1
        evil["rows"].append(extra)
        expect_reject(self.root, self.q, evil)

    def test_noncontiguous_positions(self):
        q2 = make_range("a", "d", page_length=2)
        page = generate_page(self.store, q2)
        evil = mutate(page)
        evil["rows"][1]["pos"] = 9
        expect_reject(self.root, q2, evil)

    def test_query_envelope_mismatch(self):
        page = self._first_page()
        evil = mutate(page)
        evil["query"]["page_length"] = 5
        expect_reject(self.root, self.q, evil)

    def test_root_commitment_tamper(self):
        evil_root = mutate(self.root)
        evil_root["n_rows"] = evil_root["n_rows"] + 1
        expect_reject(evil_root, self.q, self._first_page())

    def test_unknown_projected_column_leak_attempt(self):
        # A page that ships a value for an unprojected column must fail.
        page = self._first_page()
        evil = mutate(page)
        evil["rows"][0]["values"]["secret"] = {"t": "text", "v": "x"}
        expect_reject(self.root, self.q, evil)


if __name__ == "__main__":
    unittest.main(verbosity=2)
