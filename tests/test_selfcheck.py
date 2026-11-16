"""Builder self-check must catch an inconsistent authenticated index.

The builder independently recomputes every column root, row leaf and the
row-tree root before emitting the trusted root.  Simulate a corrupted write
by tampering with a row-tree internal node after assembly but before the
self-check, and require the build to fail rather than emit a root.
"""

import os
import sqlite3
import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import unittest  # noqa: E402

from relslice import BuildError, open_store  # noqa: E402
from relslice.builder import _build_row_tree, _self_verify  # noqa: E402
from helpers import HAND_ROWS, build_hand_db, make_schema  # noqa: E402


class SelfCheckTests(unittest.TestCase):
    def test_self_verify_detects_corrupt_row_node(self):
        tmp, db, schema, root = build_hand_db()
        store = open_store(db)
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE rownodes SET digest=randomblob(32) "
            "WHERE level=(SELECT MAX(level) FROM rownodes) LIMIT 1"
        )
        conn.commit()
        conn.close()
        with self.assertRaises(BuildError):
            _self_verify(
                store,
                schema,
                store.total_rows,
                bytes.fromhex(root["row_tree_root"]),
                root["snapshot_id"],
                bytes.fromhex(root["token_auth_key"]),
            )
        store.close()

    def test_self_verify_detects_corrupt_cell(self):
        tmp, db, schema, root = build_hand_db()
        store = open_store(db)
        from relslice import encoding as E

        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE cells SET enc=? WHERE pos=0 AND col_idx=1",
            (E.encode_value(424242),),
        )
        conn.commit()
        conn.close()
        with self.assertRaises(BuildError):
            _self_verify(
                store,
                schema,
                store.total_rows,
                bytes.fromhex(root["row_tree_root"]),
                root["snapshot_id"],
                bytes.fromhex(root["token_auth_key"]),
            )
        store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
