"""Client query definition and ordered-coordinate comparisons."""

from __future__ import annotations

from dataclasses import dataclass

from .encoding import EncodingError, is_bool
from .schema import Schema
from .ordering import compare_scalar


@dataclass(frozen=True)
class Query:
    """Left-closed, right-open business-key range [low, high).

    ``low`` / ``high`` contain one typed value per key column.  An empty
    range (low >= high under the key order) is legal and always yields an
    exhausted zero-row first page.
    """

    low: list[object]
    high: list[object]
    projection: tuple[str, ...]
    page_length: int

    @staticmethod
    def from_dict(obj: dict, schema: Schema) -> "Query":
        if not isinstance(obj, dict):
            raise EncodingError("query must be an object")
        low = obj.get("low")
        high = obj.get("high")
        projection = obj.get("projection")
        page_length = obj.get("page_length")
        if not isinstance(low, list) or not isinstance(high, list):
            raise EncodingError("query low/high must be lists")
        key_cols = [c for c in schema.columns if c.key]
        if len(low) != len(key_cols) or len(high) != len(key_cols):
            raise EncodingError(
                "range endpoints must have one value per key column"
            )
        low_vals, high_vals = [], []
        for col, lv, hv in zip(key_cols, low, high):
            lv = _coerce_endpoint(lv, col.name, col.col_type)
            hv = _coerce_endpoint(hv, col.name, col.col_type)
            low_vals.append(lv)
            high_vals.append(hv)
        if not isinstance(projection, list) or not projection:
            raise EncodingError("projection must be a non-empty list")
        seen: set[str] = set()
        for name in projection:
            if not isinstance(name, str):
                raise EncodingError("projection entries must be strings")
            if name not in seen:
                schema.index(name)  # raises on unknown column
                seen.add(name)
        if not isinstance(page_length, int) or isinstance(page_length, bool):
            raise EncodingError("page_length must be an integer")
        if page_length <= 0:
            raise EncodingError("page_length must be positive")
        return Query(
            low_vals, high_vals, tuple(dict.fromkeys(projection)), page_length
        )

    def to_dict(self) -> dict:
        from .encoding import value_to_wire

        return {
            "low": [value_to_wire(v) for v in self.low],
            "high": [value_to_wire(v) for v in self.high],
            "projection": list(self.projection),
            "page_length": self.page_length,
        }


def _coerce_endpoint(obj, name: str, col_type: str):
    # Endpoints arrive as typed wire shapes from JSON.
    from .encoding import value_from_wire

    value = value_from_wire(obj)
    if value is None:
        raise EncodingError(f"range endpoint for key {name!r} cannot be null")
    if col_type == "int64":
        if is_bool(value) or not isinstance(value, int):
            raise EncodingError(f"endpoint for {name!r} must be int64")
    elif col_type == "text":
        if not isinstance(value, str):
            raise EncodingError(f"endpoint for {name!r} must be text")
    elif col_type == "bool":
        if not is_bool(value):
            raise EncodingError(f"endpoint for {name!r} must be bool")
    return value


def key_less(schema: Schema, a: tuple[object, ...], b: tuple[object, ...]):
    key_cols = [c for c in schema.columns if c.key]
    for idx, col in enumerate(key_cols):
        cmp = compare_scalar(a[idx], b[idx], col.col_type)
        if cmp:
            return cmp < 0
    return False


def key_equal(a: tuple[object, ...], b: tuple[object, ...]) -> bool:
    return all(x == y and not (isinstance(x, bool) ^ isinstance(y, bool))
               for x, y in zip(a, b))


def key_in_range(schema: Schema, key: tuple[object, ...],
                 low: list[object], high: list[object]) -> bool:
    """Range membership [low, high) on business keys."""
    return (not key_less(schema, key, tuple(low))) and key_less(
        schema, key, tuple(high)
    )


def range_is_empty(schema: Schema, low: list[object], high: list[object]):
    return not key_less(schema, tuple(low), tuple(high))


def coord_equal(a_key, a_rid, b_key, b_rid) -> bool:
    return a_rid == b_rid and key_equal(a_key, b_key)
