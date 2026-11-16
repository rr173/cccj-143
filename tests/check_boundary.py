import sys
sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

from relslice import generate_page, open_store, verify_page
from relslice.encoding import value_to_wire
from helpers import build_hand_db, drain, make_range

_, db, schema, root = build_hand_db()
store = open_store(db)

# [a,d) has 3 rows; L=3 reaches the boundary in one page.
q = make_range("a", "d", page_length=3)
pages = drain(store, root, q)
assert len(pages) == 1 and pages[0]["exhausted"]
p = pages[0]
print("boundary page rows:", [r["row_id"] for r in p["rows"]])
print("exhausted:", p["exhausted"], "token:", p["next_continuation"])
# successor is the first d row, outside the range
assert p["successor"] is not None and p["successor"]["row_id"] == 40
verify_page(root, q, p)
print("boundary successor outside range, verified OK")

# non-empty range with zero matching rows [c, d)
from relslice import Query
q0 = Query.from_dict({
    "low": [value_to_wire("c")],
    "high": [value_to_wire("d")],
    "projection": ["k"],
    "page_length": 2,
}, schema)
p0 = generate_page(store, q0)
assert p0["rows"] == [] and p0["exhausted"]
verify_page(root, q0, p0)
print("zero-row non-empty range verified; pred:",
      p0["predecessor"]["key"], "succ:", p0["successor"]["key"])
store.close()
