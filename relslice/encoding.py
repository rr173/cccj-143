"""Canonical binary encoding and domain-separated SHA-256 hashing.

This module is the *public encoding specification* of the protocol.  An
independent implementer only needs this file's documentation to recompute
every digest that appears in a trusted root or in a proof.

All hashes are plain standard SHA-256 (32 bytes).  There is no signature
service: domain separation is achieved by prefixing every hashed message
with a fixed, unique ASCII tag terminated by ``|``.  Every variable-length
field is length-prefixed with a big-endian uint32, so no parsing relies on
ambiguous delimiters.

Protocol id (pinned in every digest)::

    PROTOCOL_ID = b"relslice/v1"

Value type tags (single byte, used both in chunks, SQLite cells and hashes)::

    TAG_NULL = 0x00
    TAG_BOOL = 0x01        # payload byte: 0 or 1
    TAG_INT  = 0x02        # payload: 8-byte big-endian signed int64
    TAG_TEXT = 0x03        # payload: UTF-8 bytes, compared by Unicode code point

The five value shapes are therefore mutually distinct at the byte level; in
particular ``null``, ``""``, ``"123"``, ``123`` and ``true`` all encode
differently.  Booleans are never conflated with integers (Python's
``True == 1`` trap is handled explicitly everywhere).

Framing::

    u8(b)              -> b
    u32(n)             -> 4 big-endian bytes
    u64(n)             -> 8 big-endian bytes
    lp(bytes)          -> u32(len) || bytes
    frame(tag, *parts) -> tag || lp(part0) || lp(part1) || ...
    tagged_hash(tag, *parts) = SHA256(PROTOCOL_ID || b"|" || tag || b"|"
                                      || lp(part0) || lp(part1) || ...)
"""

from __future__ import annotations

import hashlib
import struct

PROTOCOL_ID = b"relslice/v1"

TAG_NULL = 0x00
TAG_BOOL = 0x01
TAG_INT = 0x02
TAG_TEXT = 0x03

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1
_U32_MAX = (1 << 32) - 1


class EncodingError(ValueError):
    """Raised when a value cannot be encoded under the protocol."""


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u32(value: int) -> bytes:
    if not 0 <= value <= _U32_MAX:
        raise EncodingError("uint32 out of range")
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    if not 0 <= value <= (1 << 64) - 1:
        raise EncodingError("uint64 out of range")
    return struct.pack(">Q", value)


def i64(value: int) -> bytes:
    if not _INT64_MIN <= value <= _INT64_MAX:
        raise EncodingError("int64 out of range")
    return struct.pack(">q", value)


def lp(blob: bytes) -> bytes:
    return u32(len(blob)) + blob


def frame(tag: int, parts: list[bytes]) -> bytes:
    return u8(tag) + b"".join(lp(p) for p in parts)


def tagged_hash(domain: str, *parts: bytes) -> bytes:
    """SHA-256 with protocol and domain separation and length-prefixed parts."""
    h = hashlib.sha256()
    h.update(PROTOCOL_ID)
    h.update(b"|")
    h.update(domain.encode("ascii"))
    h.update(b"|")
    for part in parts:
        h.update(lp(part))
    return h.digest()


# ---------------------------------------------------------------------------
# Typed value encoding
# ---------------------------------------------------------------------------

def is_bool(value: object) -> bool:
    """Strict bool test (must run before any int test, since bool subclasses int)."""
    return isinstance(value, bool)


def encode_value(value: object) -> bytes:
    """Encode a typed scalar to its canonical byte string."""
    if value is None:
        return frame(TAG_NULL, [])
    if is_bool(value):
        return frame(TAG_BOOL, [u8(1 if value else 0)])
    if isinstance(value, int):
        if not _INT64_MIN <= value <= _INT64_MAX:
            raise EncodingError("int64 out of range")
        return frame(TAG_INT, [i64(value)])
    if isinstance(value, str):
            raw = value.encode("utf-8")
            if len(raw) > _U32_MAX:
                raise EncodingError("text too long")
            return frame(TAG_TEXT, [raw])
    raise EncodingError(f"unsupported value type: {type(value).__name__}")


def decode_value(blob: bytes) -> object:
    """Inverse of :func:`encode_value` (used when reading chunks/SQLite)."""
    if not blob:
        raise EncodingError("empty encoded value")
    tag = blob[0]
    pos = 1

    def take() -> bytes:
        nonlocal pos
        if pos + 4 > len(blob):
            raise EncodingError("truncated length prefix")
        (length,) = struct.unpack_from(">I", blob, pos)
        pos += 4
        if pos + length > len(blob):
            raise EncodingError("truncated payload")
        part = blob[pos:pos + length]
        pos += length
        return part

    if tag == TAG_NULL:
        if pos != len(blob):
            raise EncodingError("trailing bytes after null")
        return None
    if tag == TAG_BOOL:
        payload = take()
        if len(payload) != 1 or payload[0] not in (0, 1):
            raise EncodingError("bad bool payload")
        if pos != len(blob):
            raise EncodingError("trailing bytes after bool")
        return payload[0] == 1
    if tag == TAG_INT:
        payload = take()
        if len(payload) != 8:
            raise EncodingError("bad int payload")
        if pos != len(blob):
            raise EncodingError("trailing bytes after int")
        return struct.unpack(">q", payload)[0]
    if tag == TAG_TEXT:
        payload = take()
        if pos != len(blob):
            raise EncodingError("trailing bytes after text")
        return payload.decode("utf-8")
    raise EncodingError(f"unknown type tag 0x{tag:02x}")


# ---------------------------------------------------------------------------
# JSON wire shapes (proof/root payloads are JSON; hashes are hex strings)
# ---------------------------------------------------------------------------

def value_to_wire(value: object) -> dict:
    """Typed JSON shape for a scalar; preserves the five-way distinction."""
    if value is None:
        return {"t": "null"}
    if is_bool(value):
        return {"t": "bool", "v": bool(value)}
    if isinstance(value, int):
        return {"t": "int64", "v": value}
    if isinstance(value, str):
        return {"t": "text", "v": value}
    raise EncodingError(f"unsupported value type: {type(value).__name__}")


def value_from_wire(obj: object) -> object:
    if not isinstance(obj, dict) or "t" not in obj:
        raise EncodingError("malformed typed value")
    kind = obj["t"]
    if kind == "null":
        if set(obj) != {"t"}:
            raise EncodingError("malformed null")
        return None
    if kind == "bool":
        if not isinstance(obj.get("v"), bool):
            raise EncodingError("malformed bool")
        return obj["v"]
    if kind == "int64":
        v = obj.get("v")
        # JSON true/false must not be accepted as integers.
        if not isinstance(v, int) or isinstance(v, bool):
            raise EncodingError("malformed int64")
        if not _INT64_MIN <= v <= _INT64_MAX:
            raise EncodingError("int64 out of range")
        return v
    if kind == "text":
        if not isinstance(obj.get("v"), str):
            raise EncodingError("malformed text")
        return obj["v"]
    raise EncodingError(f"unknown wire type {kind!r}")


def wire_to_encoded(obj: object) -> bytes:
    """Canonical encoding of a value received over the JSON wire."""
    return encode_value(value_from_wire(obj))


def hex32(blob: bytes) -> str:
    if len(blob) != 32:
        raise EncodingError("digest must be 32 bytes")
    return blob.hex()


def from_hex32(text: str) -> bytes:
    if not isinstance(text, str):
        raise EncodingError("digest must be a hex string")
    try:
        blob = bytes.fromhex(text)
    except ValueError as exc:
        raise EncodingError("digest is not valid hex") from exc
    if len(blob) != 32:
        raise EncodingError("digest must be 32 bytes")
    return blob
