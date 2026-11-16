"""Shared fixtures and helpers for the relslice test suite.

Tests run under ``python3 -I``; the package is imported through an explicit
absolute path entry so the current working directory never participates in
module resolution.
"""

import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, "/home/node/pylib")

from relslice import (  # noqa: E402
    Query,
    Schema,
    build_snapshot,
    generate_page,
    open_store,
    verify_page,
)
from relslice.verifier import VerificationError  # noqa: E402
from relslice.encoding import EncodingError  # noqa: E402

# Fixed hand-written relation from the task statement.
# Business keys a, a, b, d, d with distinct row_ids; rows are fed to the
# builder in shuffled order on purpose.
HAND_ROWS = [
    {"k": "d", "v": 40, "row_id": 40},
    {"k": "b", "v": 30, "row_id": 30},
    {"k": "a", "v": 11, "row_id": 11},
    {"k": "d", "v": 41, "row_id": 41},
    {"k": "a", "v": 10, "row_id": 10},
]

# Expected full coordinates sorted by (k, row_id).
HAND_COORDS = [
    (("a",), 10),
    (("a",), 11),
    (("b",), 30),
    (("d",), 40),
    (("d",), 41),
]

HAND_SCHEMA_DICT = {
    "columns": [
        {"name": "k", "type": "text", "key": True},
        {"name": "v", "type": "int64", "key": False},
    ],
    "row_id_name": "row_id",
}


def make_schema():
    return Schema.from_dict(HAND_SCHEMA_DICT)


def make_range(low, high, projection=("k", "v"), page_length=1):
    return Query.from_dict(
        {
            "low": [{"t": "text", "v": low}],
            "high": [{"t": "text", "v": high}],
            "projection": list(projection),
            "page_length": page_length,
        },
        make_schema(),
    )


def build_hand_db(chunk_bytes=400):
    tmp = tempfile.mkdtemp(prefix="relslice-test-")
    db_path = os.path.join(tmp, "hand.db")
    schema = make_schema()
    root = build_snapshot(
        db_path, schema, iter(HAND_ROWS),
        snapshot_id="snap-hand", chunk_bytes=chunk_bytes,
    )
    return tmp, db_path, schema, root


def drain(store, root, query):
    """Walk all pages of a query, verifying every page offline."""
    pages = []
    token = None
    while True:
        page = generate_page(store, query, token)
        result = verify_page(root, query, page, token)
        assert result["valid"]
        pages.append(page)
        if page["exhausted"]:
            assert result["next_continuation"] is None
            break
        # Persist the client-signed credential, never the unsigned body.
        token = result["next_continuation"]
        assert "token_mac" in token
    return pages


def mutate(obj):
    """Deep-copy a JSON-like object so attack mutations stay local."""
    return copy.deepcopy(obj)


def expect_reject(root, query, page, token=None):
    try:
        verify_page(root, query, page, token)
    except (VerificationError, EncodingError):
        return
    raise AssertionError("malicious page was accepted")
