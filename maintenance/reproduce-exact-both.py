from pathlib import Path
import ast,sys,sqlite3,hashlib
assert sqlite3.sqlite_version=='3.40.1'
sys.dont_write_bytecode=True;sys.path.insert(0,str(Path.cwd()))
from relslice import Schema,build_snapshot
module=ast.parse(Path('demo/demo_large.py').read_text())
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
selected=[]
for n in main.body:
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ['schema','root'] for t in n.targets):selected.append(n)
    elif isinstance(n,ast.FunctionDef) and n.name=='rows':selected.append(n)
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='root' for t in n.targets):break
oid='3feb09dac00842992a68080ed876650172efd16ad8376964e9efe93ce19e2cb4'
out=Path('.git/lfs/objects')/oid[:2]/oid[2:4]/oid
out.parent.mkdir(parents=True,exist_ok=True)
assert not out.exists()
exec(compile(ast.Module(body=selected,type_ignores=[]),'original-demo-build','exec'),{'Schema':Schema,'build_snapshot':build_snapshot,'N_ROWS':120000,'db_path':str(out)})
h=hashlib.sha256()
with out.open('rb') as f:
    for block in iter(lambda:f.read(4*1024*1024),b''):h.update(block)
assert out.stat().st_size==160923648 and h.hexdigest()==oid
print('Original database size and SHA256 verified:',oid,flush=True)
module=ast.parse(Path('demo/demo_large.py').read_text())
main=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='main')
selected=[]
for n in main.body:
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ['small_n','small_schema','small_root'] for t in n.targets):selected.append(n)
    elif isinstance(n,ast.FunctionDef) and n.name=='small_rows':selected.append(n)
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='small_root' for t in n.targets):break
schema_nodes=[n for n in main.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='schema' for t in n.targets)]
small=Path('.git/lfs/small-reproduction.db')
exec(compile(ast.Module(body=schema_nodes+selected,type_ignores=[]),'original-small-build','exec'),{'Schema':Schema,'build_snapshot':build_snapshot,'N_ROWS':120000,'small_db':str(small)})
print('SMALL_SHA256',hashlib.sha256(small.read_bytes()).hexdigest(),flush=True)
assert small.stat().st_size==18980864 and hashlib.sha256(small.read_bytes()).hexdigest()=='d4d694781d1987ff73c96c852994631235fe96332407a0a298e32342702f2ea8'
