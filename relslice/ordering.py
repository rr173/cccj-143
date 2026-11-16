"""External sorting of unordered row inputs into full-coordinate order.

The full coordinate is the composite business key followed by the globally
unique int64 ``row_id`` as the final tie-breaker::

    (key_col_0, ..., key_col_{K-1}, row_id) ascending

Ordering rules:

* int64 values sort numerically;
* text values sort by Unicode code point (Python ``str`` order);
* booleans sort ``False`` before ``True``;
* key values are never null (rejected at validation);
* equal business keys are allowed; equal full coordinates are not (the
  ``row_id`` UNIQUE constraint in SQLite rejects duplicates).

The input is never held whole in memory.  Rows are buffered up to a byte
budget, sorted inside a chunk file, and then k-way heap-merged.
"""

from __future__ import annotations

import heapq
import os
import struct
import tempfile

from .encoding import decode_value, encode_value, i64
from .schema import Schema

DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024


def compare_scalar(a: object, b: object, col_type: str) -> int:
    # Values share the column's declared type; bool must not hit int compare
    # via Python's True==1 equivalence.
    if col_type == "bool":
        ai, bi = 1 if a else 0, 1 if b else 0
        return (ai > bi) - (ai < bi)
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def coord_less(
    schema: Schema,
    key_a: tuple[object, ...],
    rid_a: int,
    key_b: tuple[object, ...],
    rid_b: int,
) -> bool:
    for idx, col in enumerate(c for c in schema.columns if c.key):
        cmp = compare_scalar(key_a[idx], key_b[idx], col.col_type)
        if cmp:
            return cmp < 0
    return rid_a < rid_b


def _encode_record(row_id: int, values: list[object]) -> bytes:
    return i64(row_id) + b"".join(encode_value(v) for v in values)


def _decode_record(blob: bytes, schema: Schema):
    if len(blob) < 8:
        raise ValueError("corrupt chunk record")
    (row_id,) = struct.unpack(">q", blob[:8])
    pos = 8
    values = []
    for _ in range(schema.column_count):
        # encoded values are self-delimiting; find boundary by trial decode:
        # decode_value needs the exact buffer, so scan using length framing.
        tag = blob[pos]
        start = pos
        pos += 1
        if tag == 0x00:  # null: no payload
            pass
        else:
            (length,) = struct.unpack_from(">I", blob, pos)
            pos += 4 + length
        values.append(decode_value(blob[start:pos]))
    if pos != len(blob):
        raise ValueError("trailing bytes in chunk record")
    return row_id, values


class _ChunkWriter:
    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "wb")
        self.bytes_written = 0

    def write(self, record: bytes) -> None:
        self.f.write(struct.pack(">I", len(record)))
        self.f.write(record)
        self.bytes_written += 4 + len(record)

    def close(self) -> None:
        self.f.close()


class _ChunkReader:
    def __init__(self, path: str, schema: Schema, chunk_id: int):
        self.f = open(path, "rb")
        self.schema = schema
        self.chunk_id = chunk_id

    def read_record(self):
        header = self.f.read(4)
        if not header:
            return None
        if len(header) != 4:
            raise ValueError("corrupt chunk header")
        (length,) = struct.unpack(">I", header)
        blob = self.f.read(length)
        if len(blob) != length:
            raise ValueError("truncated chunk record")
        return _decode_record(blob, self.schema)

    def close(self) -> None:
        self.f.close()


def write_sorted_chunks(rows, schema: Schema, tmpdir: str,
                        chunk_bytes: int = DEFAULT_CHUNK_BYTES):
    """Consume the input iterable into sorted on-disk chunk files."""
    chunk_paths: list[str] = []
    buffer: list[tuple[tuple[object, ...], int, list[object]]] = []
    buffered_bytes = 0
    chunk_seq = 0

    def flush():
        nonlocal buffer, buffered_bytes, chunk_seq
        if not buffer:
            return
        buffer.sort(key=_sort_key)
        path = os.path.join(tmpdir, f"chunk-{chunk_seq:08d}.bin")
        chunk_seq += 1
        writer = _ChunkWriter(path)
        try:
            for _, row_id, values in buffer:
                writer.write(_encode_record(row_id, values))
        finally:
            writer.close()
        chunk_paths.append(path)
        buffer = []
        buffered_bytes = 0

    def _sort_key(item):
        # Tuples compare naturally given per-column homogeneous types; row_id
        # is appended as the final tie-breaker.
        key, row_id, _ = item
        return tuple(_sortable(v) for v in key) + (row_id,)

    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each input row must be an object")
        row_id = row.get(schema.row_id_name)
        values = []
        for col in schema.columns:
            if col.name not in row:
                raise ValueError(f"row is missing column {col.name!r}")
            values.append(row[col.name])
        schema.check_row(values, row_id)
        key = schema.business_key(values)
        estimate = len(_encode_record(row_id, values))
        buffer.append((key, row_id, values))
        buffered_bytes += estimate
        if buffered_bytes >= chunk_bytes:
            flush()
    flush()
    return chunk_paths


def _sortable(value: object):
    # Booleans sort as 0/1 which matches the declared bool order; ints and
    # strings compare naturally within their homogeneous column.
    if isinstance(value, bool):
        return 0 if not value else 1
    return value


def merge_chunks(chunk_paths, schema: Schema):
    """Yield ``(key_values, row_id, values)`` in full-coordinate order."""
    if not chunk_paths:
        return
    readers = [_ChunkReader(p, schema, i) for i, p in enumerate(chunk_paths)]
    heap: list = []
    try:
        for reader in readers:
            rec = reader.read_record()
            if rec is not None:
                row_id, values = rec
                key = schema.business_key(values)
                heapq.heappush(
                    heap,
                    (tuple(_sortable(v) for v in key), row_id,
                     reader.chunk_id, key, values),
                )
        while heap:
            _, row_id, chunk_id, key, values = heapq.heappop(heap)
            yield key, row_id, values
            rec = readers[chunk_id].read_record()
            if rec is not None:
                next_rid, next_values = rec
                next_key = schema.business_key(next_values)
                heapq.heappush(
                    heap,
                    (tuple(_sortable(v) for v in next_key), next_rid,
                     chunk_id, next_key, next_values),
                )
    finally:
        for reader in readers:
            reader.close()


def delete_chunks(chunk_paths, tmpdir: str) -> None:
    for path in chunk_paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass


def new_tmpdir(base: str | None = None) -> str:
    return tempfile.mkdtemp(prefix="relslice-sort-", dir=base)
