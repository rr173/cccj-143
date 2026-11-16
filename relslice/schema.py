"""Snapshot schema: column order, types and the composite business sort key."""

from __future__ import annotations

from dataclasses import dataclass

from .encoding import (
    TAG_BOOL,
    TAG_INT,
    TAG_TEXT,
    EncodingError,
    lp,
    u32,
    u8,
)

SUPPORTED_TYPES = ("int64", "text", "bool")
_TYPE_TAG = {"int64": TAG_INT, "text": TAG_TEXT, "bool": TAG_BOOL}
_TAG_TYPE = {TAG_INT: "int64", TAG_TEXT: "text", TAG_BOOL: "bool"}


@dataclass(frozen=True)
class Column:
    name: str
    col_type: str
    key: bool  # part of the composite business sort key

    def check_value(self, value: object) -> None:
        from .encoding import is_bool

        if value is None:
            if self.key:
                raise EncodingError(
                    f"key column {self.name!r} must not be null"
                )
            return
        if self.col_type == "int64":
            if is_bool(value) or not isinstance(value, int):
                raise EncodingError(
                    f"column {self.name!r} expects int64, got "
                    f"{type(value).__name__}"
                )
        elif self.col_type == "text":
            if not isinstance(value, str):
                raise EncodingError(
                    f"column {self.name!r} expects text, got "
                    f"{type(value).__name__}"
                )
        elif self.col_type == "bool":
            if not is_bool(value):
                raise EncodingError(
                    f"column {self.name!r} expects bool, got "
                    f"{type(value).__name__}"
                )


@dataclass(frozen=True)
class Schema:
    columns: tuple[Column, ...]
    key_names: tuple[str, ...]  # a non-empty ordered prefix of columns
    row_id_name: str

    @staticmethod
    def from_dict(obj: dict) -> "Schema":
        if not isinstance(obj, dict):
            raise EncodingError("schema must be an object")
        raw_cols = obj.get("columns")
        if not isinstance(raw_cols, list) or not raw_cols:
            raise EncodingError("schema.columns must be a non-empty list")
        cols: list[Column] = []
        seen: set[str] = set()
        for c in raw_cols:
            if not isinstance(c, dict):
                raise EncodingError("schema column must be an object")
            name = c.get("name")
            col_type = c.get("type")
            key = bool(c.get("key", False))
            if not isinstance(name, str) or not name:
                raise EncodingError("column name must be a non-empty string")
            if name in seen:
                raise EncodingError(f"duplicate column name {name!r}")
            seen.add(name)
            if col_type not in SUPPORTED_TYPES:
                raise EncodingError(
                    f"column {name!r} has unsupported type {col_type!r}"
                )
            cols.append(Column(name, col_type, key))
        key_names = tuple(c.name for c in cols if c.key)
        if not key_names:
            raise EncodingError("schema must declare at least one key column")
        # key columns must form a prefix
        prefix = tuple(c.name for c in cols[: len(key_names)])
        if prefix != key_names:
            raise EncodingError("key columns must form a prefix of columns")
        row_id_name = obj.get("row_id_name", "row_id")
        if not isinstance(row_id_name, str) or not row_id_name:
            raise EncodingError("row_id_name must be a non-empty string")
        if row_id_name in seen:
            raise EncodingError("row_id_name must not collide with a column")
        return Schema(tuple(cols), key_names, row_id_name)

    def to_dict(self) -> dict:
        return {
            "columns": [
                {"name": c.name, "type": c.col_type, "key": c.key}
                for c in self.columns
            ],
            "row_id_name": self.row_id_name,
        }

    @property
    def column_count(self) -> int:
        return len(self.columns)

    def index(self, name: str) -> int:
        for i, c in enumerate(self.columns):
            if c.name == name:
                return i
        raise EncodingError(f"unknown projected column {name!r}")

    def check_row(self, values: list[object], row_id: int) -> None:
        from .encoding import is_bool

        if not isinstance(row_id, int) or is_bool(row_id):
            raise EncodingError("row_id must be an int64 integer")
        if not -(1 << 63) <= row_id <= (1 << 63) - 1:
            raise EncodingError("row_id outside int64 range")
        if len(values) != self.column_count:
            raise EncodingError(
                f"row has {len(values)} values, schema has "
                f"{self.column_count} columns"
            )
        for col, value in zip(self.columns, values):
            col.check_value(value)

    def business_key(self, values: list[object]) -> tuple[object, ...]:
        return tuple(values[i] for i, c in enumerate(self.columns) if c.key)

    def canonical(self) -> bytes:
        """Canonical byte encoding committed inside the trusted root."""
        parts = [u32(self.column_count)]
        for col in self.columns:
            parts.append(lp(col.name.encode("utf-8")))
            parts.append(u8(_TYPE_TAG[col.col_type]))
            parts.append(u8(1 if col.key else 0))
        parts.append(lp(self.row_id_name.encode("utf-8")))
        parts.append(u32(len(self.key_names)))
        return b"".join(parts)
