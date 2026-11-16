"""Command line interface: build / page / verify.

Examples
--------
python -m relslice.cli build --schema schema.json --rows rows.jsonl \\
    --db snapshot.db --root root.json

python -m relslice.cli page --db snapshot.db --query query.json \\
    --continuation token.json --out page.json

python -m relslice.cli verify --root root.json --query query.json \\
    --page page.json --continuation token.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .api import dump_json, load_json
from .builder import build_snapshot
from .pager import generate_page, open_store
from .query import Query
from .root import parse_and_check_root
from .schema import Schema
from .verifier import verify_page


def _read_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid JSON on line {line_no}: {exc}")


def cmd_build(args) -> int:
    schema = Schema.from_dict(load_json(args.schema))
    root = build_snapshot(
        args.db, schema, _read_jsonl(args.rows),
        snapshot_id=args.snapshot_id,
        chunk_bytes=args.chunk_bytes,
    )
    dump_json(args.root, root)
    print(
        json.dumps(
            {
                "built": True,
                "db": args.db,
                "root": args.root,
                "snapshot_id": root["snapshot_id"],
                "n_rows": root["n_rows"],
                "row_tree_root": root["row_tree_root"],
            },
            indent=2,
        )
    )
    return 0


def cmd_page(args) -> int:
    store = open_store(args.db)
    try:
        schema = store.schema
        query = Query.from_dict(load_json(args.query), schema)
        continuation = load_json(args.continuation) if args.continuation else None
        page = generate_page(store, query, continuation)
    finally:
        store.close()
    dump_json(args.out, page)
    print(json.dumps({"page": args.out, "read_counts": page["read_counts"]},
                     indent=2))
    return 0


def cmd_verify(args) -> int:
    root_obj = load_json(args.root)
    schema, _, _, _, _ = parse_and_check_root(root_obj)
    query = Query.from_dict(load_json(args.query), schema)
    page = load_json(args.page)
    continuation = (
        load_json(args.continuation) if args.continuation else None
    )
    result = verify_page(root_obj, query, page, continuation)
    if args.save_continuation and result["next_continuation"] is not None:
        dump_json(args.save_continuation, result["next_continuation"])
        result["saved_continuation"] = args.save_continuation
    print(json.dumps(result, indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="relslice")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="build an authenticated snapshot")
    p_build.add_argument("--schema", required=True)
    p_build.add_argument("--rows", required=True)
    p_build.add_argument("--db", required=True)
    p_build.add_argument("--root", required=True)
    p_build.add_argument("--snapshot-id", default=None)
    p_build.add_argument("--chunk-bytes", type=int, default=8 * 1024 * 1024)
    p_build.set_defaults(func=cmd_build)

    p_page = sub.add_parser("page", help="generate one slice page")
    p_page.add_argument("--db", required=True)
    p_page.add_argument("--query", required=True)
    p_page.add_argument("--continuation", default=None)
    p_page.add_argument("--out", required=True)
    p_page.set_defaults(func=cmd_page)

    p_verify = sub.add_parser("verify", help="verify a page offline")
    p_verify.add_argument("--root", required=True)
    p_verify.add_argument("--query", required=True)
    p_verify.add_argument("--page", required=True)
    p_verify.add_argument("--continuation", default=None)
    p_verify.add_argument(
        "--save-continuation",
        default=None,
        help="write the keyed continuation credential for the next page",
    )
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
