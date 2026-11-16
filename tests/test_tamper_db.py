"""Database-level tampering: a malicious distributor edits stored digests.

These tests mutate the SQLite file itself (row node, column node and cell
tables) and require that every page produced from the corrupted store is
rejected by the offline verifier against the original trusted root.
"""

import os
import shutil
import sqlite3
import sys

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

import unittest  # noqa: E402

from relslice import generate_page, open_store, verify_page  # noqa: E402
from helpers import build_hand_db, expect_reject, make_range  # noqa: E402


def corrupt(db_path, sql):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute(sql)
    conn.commit()
    conn.close()


class StorageTamperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.db, cls.schema, cls.root = build_hand_db()
        cls.q = make_range("a", "d", page_length=2)

    def _copy_db(self, name):
        path = os.path.join(self.tmp, name)
        shutil.copyfile(self.db, path)
        # drop WAL side files so the copy is self-contained
        for suffix in ("-wal", "-shm"):
            side = path + suffix
            if os.path.exists(side):
                os.remove(side)
        return path

    def test_tampered_row_index_node_rejected(self):
        # Corrupt a row-tree node that this page's proof actually opens.
        db = self._copy_db("row_node.db")
        store = open_store(db)
        page = generate_page(store, self.q)
        node = next(
            n for n in page["row_proof"]["nodes"] if n["level"] >= 1
        )
        store.close()
        corrupt(
            db,
            f"UPDATE rownodes SET digest=randomblob(32) "
            f"WHERE level={node['level']} AND idx={node['idx']}",
        )
        store = open_store(db)
        page = generate_page(store, self.q)
        expect_reject(self.root, self.q, page)
        store.close()

    def test_tampered_column_index_node_rejected(self):
        # Use a projection that leaves hidden sibling cells, then corrupt a
        # column-tree proof node the page genuinely relies on.
        qv = make_range("a", "d", projection=("v",), page_length=2)
        db = self._copy_db("col_node.db")
        store = open_store(db)
        page = generate_page(store, qv)
        pos = str(page["rows"][0]["pos"])
        node = page["column_proofs"][pos]["nodes"][0]
        store.close()
        corrupt(
            db,
            f"UPDATE colnodes SET digest=randomblob(32) "
            f"WHERE pos={pos} AND level={node['level']} AND idx={node['idx']}",
        )
        store = open_store(db)
        page = generate_page(store, qv)
        expect_reject(self.root, qv, page)
        store.close()

    def test_tampered_cell_rejected(self):
        db = self._copy_db("cell.db")
        # Flip a projected cell to a different (still well-typed) value.
        from relslice import encoding as E

        new_enc = E.encode_value(999999)
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE cells SET enc=? WHERE pos=0 AND col_idx=1", (new_enc,)
        )
        conn.commit()
        conn.close()
        store = open_store(db)
        page = generate_page(store, self.q)
        expect_reject(self.root, self.q, page)
        store.close()

    def test_tampered_leaf_row_id_rejected(self):
        db = self._copy_db("leaf.db")
        corrupt(db, "UPDATE leaves SET row_id=row_id+1000 WHERE pos=0")
        store = open_store(db)
        page = generate_page(store, self.q)
        expect_reject(self.root, self.q, page)
        store.close()

    def test_deleted_leaf_gap_rejected(self):
        db = self._copy_db("delete.db")
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM leaves WHERE pos=1")
        conn.commit()
        conn.close()
        store = open_store(db)
        # Paging must fail loudly rather than silently skipping the row.
        with self.assertRaises(Exception):
            generate_page(store, self.q)
        store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
