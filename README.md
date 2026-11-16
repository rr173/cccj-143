# relslice — 离线关系切片认证交付工具

资料中心构建一次**有序认证索引**并保管可信根凭据；不可信分发节点只持有
SQLite 快照，提供区间分页与列投影；独立客户仅凭**可信根、原始查询、返回
证明、此前已验证的续页凭据**离线验证每页完整性。逐行摘要无法发现的漏行、
重排、重复、跨快照拼接等攻击，在这里由位置化 Merkle 行树 + 边界材料 +
绑定区间的续页凭据共同阻止。

- 存储：SQLite（`relslice/storage.py`）
- 哈希：标准 SHA-256，域分离标签，无签名服务（`relslice/encoding.py`）
- 公开规范：[`PROTOCOL.md`](./PROTOCOL.md)（独立程序可据此重算全部摘要）

## 目录结构

```
relslice/
  encoding.py   类型化编码、域分离哈希、JSON wire 形状（公开规范的参考实现）
  schema.py     列/类型/复合排序键声明与校验
  ordering.py   外存排序：分块落盘 + k 路堆归并，不把整份数据装入内存
  trees.py      列树、行树、最小兄弟补集、根重算
  storage.py    SQLite 表结构与逐次递增的真实读取计数器
  builder.py    构建流水线 + 构建期独立自校验
  root.py       可信根凭据与续页凭据格式
  query.py      查询对象、区间与坐标比较
  pager.py      分发端分页、定位、最小证明生成
  verifier.py   独立离线验证器（不接触数据库/分发节点）
  cli.py        build / page / verify 命令
tests/          69 个测试：手写坐标、手写根、攻击、坏输入、库级篡改、CLI
demo/           十万行以上窄页读取规模演示
PROTOCOL.md     实现无关的公开编码与认证规范
```

## 快速开始

```bash
# 构建（rows 为 JSON Lines，可无序；row_id 唯一性由构建器强制）
python -m relslice.cli build \
  --schema schema.json --rows rows.jsonl \
  --db snapshot.db --root root.json

# 分发端出一页
python -m relslice.cli page \
  --db snapshot.db --query query.json --out page.json

# 客户离线验证（无需数据库、无需网络），并把签名后的续页凭据另存
python -m relslice.cli verify --root root.json --query query.json \
  --page page.json --save-continuation token.json

# 下一页请求使用客户保存的签名 token
python -m relslice.cli page --db snapshot.db --query query.json \
  --continuation token.json --out page2.json
```

可调用 API：

```python
from relslice import (
    Schema, Query, build_snapshot, open_store,
    generate_page, verify_page,
)

schema = Schema.from_dict({...})
root = build_snapshot("snap.db", schema, rows_iterable)
store = open_store("snap.db")
query = Query.from_dict({...}, schema)
page = generate_page(store, query)
assert verify_page(root, query, page)["valid"]
```

## 认证结构（概览）

- **列树（每行一棵，C+1 叶）**：叶 0 承诺完整坐标，叶 j+1 承诺第 j 列值。
  投影只开放坐标叶与被投影列叶，其他业务列仅以兄弟摘要出现，不泄漏明文。
- **行树（每快照一棵，N 叶）**：行叶把位置、完整坐标与该行列树根绑定；
  漏行/重排/重复/跨快照材料都会使根重算失败。
- **边界材料**：每页携带区间窗口相邻的前驱/后继坐标与列根（仅摘要），
  用于证明“本页从正确位置开始”“已尽 / 还有后继”，不需要携带整份关系。
- **续页凭据**：分发端不持有密钥，只产出无 MAC 令牌体；客户用可信根中的
  每快照 `token_auth_key` 在本地计算 HMAC-SHA256 并保存签名凭据。改区间、
  改快照、改锚点或分发端自造锚点均离线失败；换投影或页长不跳过任何行。
  令牌密钥只存在于根凭据，从不写入分发数据库。

## 信任边界与已知泄漏（明确声明）

1. 可信根只来自资料中心带外渠道；**分发包自带的根一律不信任**。根内含
   `token_auth_key` 秘密，分发端无法替换客户已保存的根，也无法取得该密钥
   来伪造续页锚点。
2. 分发端可读取全快照（威胁模型假设如此）。它可以改行、漏行、重排、重复、
   换列、拼接另一快照材料；这些都会被验证器拒绝，但本方案不隐藏分发端
   本来就能看到的数据。
3. 排序键与 `row_id` 即使未投影也会随页公开（坐标叶与边界材料需要它们
   才能验证边界与连续性）。这是**有意的泄漏**，文档与规范均明确说明。
4. 本方案**不声称**隐藏结果条数、键分布，也不阻止对键空间的字典猜测；
   行总数 `n_rows`、页位置与坐标均出现在认证材料中。
5. 不提供签名服务、不提供访问控制或加密；机密性需要在本工具之外解决。

## 测试

```bash
cd tests
for f in test_*.py; do python3 -I "$f"; done
```

覆盖：手写 a,a,b,d,d 关系在页长 1/2/3 下的完整坐标与已尽标志、重复 a
不漏不重、换投影/页长续页取同一后缀、按规范手算小树根、七类攻击（删中间
行、跳首行、重复尾行、伪称已尽、后页冒充首页、交换列值、混另一快照）、
改续页区间、多余/缺失/冲突证明节点、空区间/空快照、同键组中间续页、超大
文本、全 null 投影列、SQLite 索引/单元/叶子篡改、坏输入与畸形证明。

## 大规模演示

```bash
python3 -I demo/demo_large.py
```

构建 120,000 行、6 列快照（外存归并排序，分块预算 2 MiB），随后从键空间
深处出 5 行窄页、只投影 2 列。实测每页读取约 80 个索引/值单元，与
`O(log N + k·(1 + m·log(C+1)))` 相符且不随 N 增长；页负载中只出现投影列，
未投影列文本不出现于响应任何位置。
