"""Public callable API for the relslice offline slice-delivery tool."""

from __future__ import annotations

import json

from .builder import BuildError, build_snapshot
from .encoding import EncodingError
from .pager import PagerError, generate_page, open_store
from .query import Query
from .root import (
    make_continuation,
    parse_and_check_root,
    sign_continuation_body,
)
from .schema import Schema
from .verifier import VerificationError, verify_page
from . import encoding, trees

__all__ = [
    "BuildError",
    "EncodingError",
    "PagerError",
    "VerificationError",
    "Query",
    "Schema",
    "build_snapshot",
    "open_store",
    "generate_page",
    "verify_page",
    "load_query",
    "load_json",
    "dump_json",
    "encoding",
    "trees",
    "parse_and_check_root",
    "make_continuation",
    "sign_continuation_body",
]


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def dump_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def load_query(path: str, schema: Schema) -> Query:
    return Query.from_dict(load_json(path), schema)
