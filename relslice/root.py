"""Trusted root credential and continuation-token formats.

Trusted root (JSON file produced by the builder, held by the data center and
delivered to clients through an out-of-band trusted channel; a root shipped
inside a distribution package must never be trusted)::

    {
      "format": "relslice-root",
      "version": 1,
      "protocol_id": "relslice/v1",
      "snapshot_id": "<hex>",
      "schema": { ... },
      "n_rows": N,
      "column_count": C,
      "row_tree_root": "<hex32>",
      "token_auth_key": "<hex32, secret>",
      "root_commitment": "<hex32>"
    }

The ``token_auth_key`` is a 32-byte random secret generated per snapshot.
It lives only in the trusted root credential: it is never written into the
distributor's SQLite database, so a node that can read or rewrite the whole
snapshot still cannot mint valid continuation anchors.  The
``root_commitment`` is a domain-separated hash over every other field, so
schema, snapshot identity, ordering protocol, row count, row-tree root and
the token key are all bound together.  This is standard SHA-256 plus
HMAC-SHA-256, not a signature service.

Continuation credentials bind snapshot identity, the exact query range, the
sorting protocol and the next full coordinate, authenticated with
HMAC-SHA-256 under the root's secret key.  Any tampering (including changing
the range) -- and any anchor forged by the distributor without the key -- is
detected offline.

    token = { ...fields..., "token_mac": "<hex32>" }
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid

from . import encoding as E
from .schema import Schema

ROOT_FORMAT = "relslice-root"
ROOT_VERSION = 1
TOKEN_KEY_BYTES = 32


def _key_canonical(key: tuple[object, ...] | list[object]) -> bytes:
    return E.u32(len(key)) + b"".join(E.encode_value(v) for v in key)


def new_token_auth_key() -> bytes:
    return secrets.token_bytes(TOKEN_KEY_BYTES)


def compute_root_commitment(
    snapshot_id: str,
    schema: Schema,
    n_rows: int,
    row_tree_root: bytes,
    token_auth_key: bytes,
) -> bytes:
    return E.tagged_hash(
        "root",
        E.PROTOCOL_ID,
        E.lp(snapshot_id.encode("utf-8")),
        schema.canonical(),
        E.u64(n_rows),
        E.u32(schema.column_count),
        row_tree_root,
        token_auth_key,
    )


def build_root_dict(
    snapshot_id: str,
    schema: Schema,
    n_rows: int,
    row_tree_root: bytes,
    token_auth_key: bytes,
) -> dict:
    if len(token_auth_key) != TOKEN_KEY_BYTES:
        raise E.EncodingError("token_auth_key must be 32 bytes")
    commitment = compute_root_commitment(
        snapshot_id, schema, n_rows, row_tree_root, token_auth_key
    )
    return {
        "format": ROOT_FORMAT,
        "version": ROOT_VERSION,
        "protocol_id": E.PROTOCOL_ID.decode("ascii"),
        "snapshot_id": snapshot_id,
        "schema": schema.to_dict(),
        "n_rows": n_rows,
        "column_count": schema.column_count,
        "row_tree_root": E.hex32(row_tree_root),
        "token_auth_key": E.hex32(token_auth_key),
        "root_commitment": E.hex32(commitment),
    }


def parse_and_check_root(obj: dict):
    """Validate a root and return (schema, n_rows, row_root, snap_id, key)."""
    if not isinstance(obj, dict):
        raise E.EncodingError("root must be a JSON object")
    if obj.get("format") != ROOT_FORMAT or obj.get("version") != ROOT_VERSION:
        raise E.EncodingError("unsupported root format/version")
    if obj.get("protocol_id") != E.PROTOCOL_ID.decode("ascii"):
        raise E.EncodingError("protocol id mismatch; refusing foreign root")
    snapshot_id = obj.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise E.EncodingError("bad snapshot_id in root")
    schema = Schema.from_dict(obj["schema"])
    n_rows = obj.get("n_rows")
    if not isinstance(n_rows, int) or isinstance(n_rows, bool) or n_rows < 0:
        raise E.EncodingError("bad n_rows in root")
    if obj.get("column_count") != schema.column_count:
        raise E.EncodingError("column_count disagrees with schema")
    row_root = E.from_hex32(obj.get("row_tree_root", ""))
    token_key = E.from_hex32(obj.get("token_auth_key", ""))
    if len(token_key) != TOKEN_KEY_BYTES:
        raise E.EncodingError("bad token_auth_key in root")
    expected = compute_root_commitment(
        snapshot_id, schema, n_rows, row_root, token_key
    )
    if E.from_hex32(obj.get("root_commitment", "")) != expected:
        raise E.EncodingError("root_commitment mismatch; untrusted root")
    return schema, n_rows, row_root, snapshot_id, token_key


def new_snapshot_id() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Continuation tokens (keyed HMAC)
# ---------------------------------------------------------------------------

def _continuation_message(body: dict) -> bytes:
    low = tuple(E.value_from_wire(v) for v in body["low"])
    high = tuple(E.value_from_wire(v) for v in body["high"])
    next_key = tuple(E.value_from_wire(v) for v in body["next_key"])
    return b"".join(
        [
            E.PROTOCOL_ID,
            b"|cont|",
            E.lp(body["snapshot_id"].encode("utf-8")),
            _key_canonical(low),
            _key_canonical(high),
            _key_canonical(next_key),
            E.i64(body["next_row_id"]),
        ]
    )


def sign_continuation_body(body: dict, token_auth_key: bytes) -> dict:
    """Attach the keyed MAC to an unsigned continuation body."""
    required = {
        "format", "version", "protocol_id", "snapshot_id",
        "low", "high", "next_key", "next_row_id",
    }
    if set(body) != required:
        raise E.EncodingError("malformed continuation body")
    if body["format"] != "relslice-continuation" or body["version"] != 1:
        raise E.EncodingError("bad continuation body")
    token = dict(body)
    mac = hmac.new(
        token_auth_key, _continuation_message(body), hashlib.sha256
    ).digest()
    token["token_mac"] = E.hex32(mac)
    return token


def make_continuation(
    token_auth_key: bytes,
    snapshot_id: str,
    low: list[object],
    high: list[object],
    next_key: tuple[object, ...],
    next_row_id: int,
) -> dict:
    if not isinstance(next_row_id, int) or isinstance(next_row_id, bool):
        raise E.EncodingError("bad next_row_id in continuation")
    if not -(1 << 63) <= next_row_id <= (1 << 63) - 1:
        raise E.EncodingError("next_row_id outside int64 range")
    body = {
        "format": "relslice-continuation",
        "version": 1,
        "protocol_id": E.PROTOCOL_ID.decode("ascii"),
        "snapshot_id": snapshot_id,
        "low": [E.value_to_wire(v) for v in low],
        "high": [E.value_to_wire(v) for v in high],
        "next_key": [E.value_to_wire(v) for v in next_key],
        "next_row_id": next_row_id,
    }
    return sign_continuation_body(body, token_auth_key)


def read_continuation_fields(token: dict):
    """Read token fields without the secret key.

    Used only by the keyless distributor to position the next page.  This
    provides no authenticity: clients always validate the MAC through
    :func:`parse_continuation` using the key from their trusted root.
    """
    if not isinstance(token, dict):
        raise E.EncodingError("continuation must be an object")
    if token.get("format") != "relslice-continuation":
        raise E.EncodingError("bad continuation format")
    if token.get("version") != 1:
        raise E.EncodingError("bad continuation version")
    if token.get("protocol_id") != E.PROTOCOL_ID.decode("ascii"):
        raise E.EncodingError("continuation protocol id mismatch")
    snapshot_id = token["snapshot_id"]
    low = [E.value_from_wire(v) for v in token["low"]]
    high = [E.value_from_wire(v) for v in token["high"]]
    next_key = tuple(E.value_from_wire(v) for v in token["next_key"])
    next_row_id = token["next_row_id"]
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise E.EncodingError("bad snapshot_id in continuation")
    if not isinstance(next_row_id, int) or isinstance(next_row_id, bool):
        raise E.EncodingError("bad next_row_id in continuation")
    if not -(1 << 63) <= next_row_id <= (1 << 63) - 1:
        raise E.EncodingError("next_row_id outside int64 range")
    return snapshot_id, low, high, next_key, next_row_id


def parse_continuation(token: dict, token_auth_key: bytes):
    """Validate a token's keyed MAC and return its bound fields."""
    if not isinstance(token, dict):
        raise E.EncodingError("continuation must be an object")
    if token.get("format") != "relslice-continuation":
        raise E.EncodingError("bad continuation format")
    if token.get("version") != 1:
        raise E.EncodingError("bad continuation version")
    if token.get("protocol_id") != E.PROTOCOL_ID.decode("ascii"):
        raise E.EncodingError("continuation protocol id mismatch")
    provided = token.get("token_mac")
    body = {k: v for k, v in token.items() if k != "token_mac"}
    expected = hmac.new(
        token_auth_key, _continuation_message(body), hashlib.sha256
    ).digest()
    try:
        given = E.from_hex32(provided or "")
    except E.EncodingError as exc:
        raise E.EncodingError("continuation token mac malformed") from exc
    if not hmac.compare_digest(given, expected):
        raise E.EncodingError("continuation token MAC mismatch")
    snapshot_id = token["snapshot_id"]
    low = [E.value_from_wire(v) for v in token["low"]]
    high = [E.value_from_wire(v) for v in token["high"]]
    next_key = tuple(E.value_from_wire(v) for v in token["next_key"])
    next_row_id = token["next_row_id"]
    if not isinstance(next_row_id, int) or isinstance(next_row_id, bool):
        raise E.EncodingError("bad next_row_id in continuation")
    if not -(1 << 63) <= next_row_id <= (1 << 63) - 1:
        raise E.EncodingError("next_row_id outside int64 range")
    return snapshot_id, low, high, next_key, next_row_id


def dump_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2)
