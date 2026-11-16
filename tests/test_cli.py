"""End-to-end CLI test: build, page and verify through command line."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, "/home/node/pylib")

REPO = "/workspace"


def run_cli(*args):
    # Plain (non-isolated) invocation with the trusted repo as cwd: the
    # empty sys.path entry resolves the relslice package from /workspace.
    # Untrusted data is always passed by absolute path in a separate dir.
    return subprocess.run(
        [sys.executable, "-m", "relslice.cli", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )


class CliTests(unittest.TestCase):
    def test_full_cli_flow(self):
        work = tempfile.mkdtemp(prefix="relslice-cli-")
        schema_path = os.path.join(work, "schema.json")
        rows_path = os.path.join(work, "rows.jsonl")
        db_path = os.path.join(work, "snap.db")
        root_path = os.path.join(work, "root.json")
        query_path = os.path.join(work, "query.json")
        page_path = os.path.join(work, "page.json")
        token_path = os.path.join(work, "token.json")

        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "columns": [
                        {"name": "k", "type": "text", "key": True},
                        {"name": "v", "type": "int64", "key": False},
                    ],
                    "row_id_name": "row_id",
                },
                f,
            )
        with open(rows_path, "w", encoding="utf-8") as f:
            for row in [
                {"k": "d", "v": 4, "row_id": 40},
                {"k": "a", "v": 1, "row_id": 10},
                {"k": "b", "v": 3, "row_id": 30},
                {"k": "a", "v": 2, "row_id": 11},
            ]:
                f.write(json.dumps(row) + "\n")

        build = run_cli(
            "build", "--schema", schema_path, "--rows", rows_path,
            "--db", db_path, "--root", root_path,
        )
        self.assertIn('"built": true', build.stdout)

        with open(query_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "low": [{"t": "text", "v": "a"}],
                    "high": [{"t": "text", "v": "d"}],
                    "projection": ["v"],
                    "page_length": 2,
                },
                f,
            )

        run_cli(
            "page", "--db", db_path, "--query", query_path,
            "--out", page_path,
        )
        with open(page_path, encoding="utf-8") as f:
            page = json.load(f)
        self.assertEqual([r["row_id"] for r in page["rows"]], [10, 11])

        verify = run_cli(
            "verify", "--root", root_path, "--query", query_path,
            "--page", page_path,
            "--save-continuation", token_path,
        )
        self.assertIn('"valid": true', verify.stdout)
        with open(token_path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertIn("token_mac", saved)

        run_cli(
            "page", "--db", db_path, "--query", query_path,
            "--continuation", token_path, "--out", page_path,
        )
        verify2 = run_cli(
            "verify", "--root", root_path, "--query", query_path,
            "--page", page_path, "--continuation", token_path,
        )
        self.assertIn('"valid": true', verify2.stdout)
        with open(page_path, encoding="utf-8") as f:
            last = json.load(f)
        self.assertEqual([r["row_id"] for r in last["rows"]], [30])
        self.assertTrue(last["exhausted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
