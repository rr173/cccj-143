import os
import random
import shutil
import sys
import tempfile

sys.path.insert(0, "/home/node/pylib")
sys.path.insert(0, "/workspace/tests")

from relslice import BuildError, build_snapshot, open_store
from helpers import make_schema

schema = make_schema()
tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "x.db")
try:
    build_snapshot(db, schema, iter([{"k": None, "v": 1, "row_id": 1}]))
except BuildError as exc:
    print("build rejected:", exc)
print("db removed:", not os.path.exists(db))
sort_dirs = [
    n for n in os.listdir(tempfile.gettempdir())
    if n.startswith("relslice-sort-")
]
print("sort dirs all gone:", all(
    not os.path.exists(os.path.join(tempfile.gettempdir(), n))
    for n in sort_dirs
))

rows = [{"k": f"k{i:04d}", "v": i, "row_id": i} for i in range(500)]
random.seed(1)
random.shuffle(rows)
db2 = os.path.join(tmp, "m.db")
root = build_snapshot(db2, schema, iter(rows), chunk_bytes=256)
print("multi-chunk rows:", root["n_rows"])
store = open_store(db2)
prev = None
last_pos = -1
for pos, rid, key_enc, _, _ in store.iter_all_positions():
    key = store.decode_key(key_enc)
    if prev is not None:
        assert prev < (key, rid)
    prev = (key, rid)
    last_pos = pos
print("strict order across chunks OK; max pos:", last_pos)
store.close()
shutil.rmtree(tmp)
