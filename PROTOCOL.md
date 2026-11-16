# relslice v1 — 公开编码与认证规范

本规范是实现无关的：独立程序仅凭本文档即可重算可信根、节点摘要、列承诺、
行叶子、续页凭据哈希并验证任意一页。所有哈希均为标准 SHA-256（32 字节），
无签名服务；域分离通过 ASCII 域标签与长度前缀实现。参考实现见
`relslice/encoding.py`、`relslice/trees.py`、`relslice/root.py`。

## 1. 基础构件

固定协议标识：

```
PROTOCOL_ID = b"relslice/v1"
```

整数编码（大端）：

| 构件 | 字节 |
| --- | --- |
| `u8(n)` | 1 |
| `u32(n)` | 4 |
| `u64(n)` | 8 |
| `i64(n)` | 8（有符号） |
| `lp(b)` | `u32(len(b)) || b` |

域分离哈希（所有被哈希消息均为长度前缀分块，杜绝模糊分隔符）：

```
tagged_hash(domain, p0, p1, ...) =
    SHA256( PROTOCOL_ID || b"|" || domain || b"|"
            || lp(p0) || lp(p1) || ... )
```

`domain` 为下列 ASCII 标签之一：

```
colleaf  colnode  colempty
rowleaf  rownode  rowempty
root
cont  (HMAC-SHA256 domain under token_auth_key, not a plain hash)
```

不同标签的摘要在密码学上互不兼容；节点哈希还绑定层级与位置，节点无法在
其他位置或另一棵树中重放。

## 2. 类型化标量编码

业务标量先按类型打标签再做长度分帧：

```
encode(v) = u8(tag) || lp(payload)
```

| 类型 | tag | payload |
| --- | --- | --- |
| null | `0x00` | 空 |
| bool | `0x01` | `u8(0|1)` |
| int64 | `0x02` | `i64(v)` |
| text | `0x03` | UTF-8 字节 |

因此 null、空串 `""`、字符串数字 `"123"`、整数 `123`、布尔 `true` 的字节
编码两两不同；`true` 与 `1` 也不同（实现中布尔判断先于整数判断）。文本按
Unicode 码点排序（等价于 Python 3 的 `str` 字典序），int64 按数值排序，
bool 按 `false < true` 排序。键列不允许 null。

## 3. Schema 规范

Schema 声明列名、类型（`int64|text|bool`）、是否属于复合业务排序键，以及
全局 `row_id` 列名。键列必须构成列前缀，至少一个。完整坐标为

```
(key_col_0, ..., key_col_{K-1}, row_id)
```

业务键非 null；`row_id` 为全局唯一 int64，作为最终决胜键。相同业务键、
相同业务内容但 `row_id` 不同的行全部保留。Schema 的规范化字节串 `S`：

```
S = u32(C)
 || for each column in order:
        lp(name_utf8) || u8(type_tag) || u8(is_key)
 || lp(row_id_name_utf8)
 || u32(K)
```

其中 `type_tag` 为 `0x01 bool / 0x02 int64 / 0x03 text`。

## 4. 列树（每行一棵，C+1 个叶子）

叶子 0 为坐标叶，叶子 `j+1` 为第 `j` 个业务列的值承诺叶。

坐标负载：

```
coord_payload(key, row_id) =
    lp(encode(key_0)) || ... || lp(encode(key_{K-1})) || i64(row_id)
```

叶子摘要：

```
colleaf_digest(i, payload) = tagged_hash("colleaf", u32(i), payload)
coord_leaf  = colleaf_digest(0, coord_payload(key, row_id))
cell_leaf_j = colleaf_digest(j+1, encode(value_j))
```

内部节点与空位（位置绑定）：

```
colnode(level+1, idx, L, R) =
    tagged_hash("colnode", u32(level+1), u64(idx), L, R)
colempty(level, idx) =
    tagged_hash("colempty", u32(level), u64(idx))
```

树为位置化完全二叉结构：第 h 层节点数为上一层的 `ceil(n/2)`；奇数节点与
同层空位摘要配对。投影只开放叶子 0 与被投影列对应的叶子，其余列只以
包含证明中的兄弟摘要出现，不暴露明文。

## 5. 行树（每快照一棵，N 个叶子）

第 `pos` 个行叶子把坐标与该行列树根绑定到具体位置：

```
rowleaf(pos, key, row_id, col_root) =
    tagged_hash("rowleaf", u64(pos), coord_payload(key, row_id), col_root)
```

内部节点与空位：

```
rownode(level+1, idx, L, R) =
    tagged_hash("rownode", u32(level+1), u64(idx), L, R)
rowempty(level, idx) =
    tagged_hash("rowempty", u32(level), u64(idx))
```

空快照（N=0）的行树根定义为 `rowempty(0, 0)`。

## 6. 可信根凭据

资料中心构建器输出、客户经带外可信渠道取得的 JSON：

```json
{
  "format": "relslice-root",
  "version": 1,
  "protocol_id": "relslice/v1",
  "snapshot_id": "<hex>",
  "schema": { ... },
  "n_rows": N,
  "column_count": C,
  "row_tree_root": "<hex32>",
  "token_auth_key": "<hex32 secret>",
  "root_commitment": "<hex32>"
}
```

`token_auth_key` 是每快照 32 字节随机密钥，仅存在于可信根凭据中，
**绝不写入分发端 SQLite 数据库**。因此能读取/改写整份快照的分发节点也
无法伪造有效的续页锚点。这是标准 SHA-256 与 HMAC-SHA-256 的应用，不
实现签名服务。承诺摘要绑定协议、快照身份、schema/排序编码、总行数、列数、
行树根与令牌密钥：

```
root_commitment =
    tagged_hash("root",
        PROTOCOL_ID,
        lp(snapshot_id_utf8),
        S,
        u64(N),
        u32(C),
        row_tree_root,
        token_auth_key)
```

分发包自带的新根不得信任；客户只接受事先保存的根。

## 7. 查询与续页凭据

查询给出业务键左闭右开区间 `[low, high)`、投影列次序、正整数页长 L。
`low >= high` 为合法空区间。页语义：返回区间内完整坐标严格大于上一页
末行（首页即 `>= low`）的前 L 行，不足 L 行则返回全部余行，按完整坐标
递增。

续页凭据命名“下一页首行的精确完整坐标”，并绑定同一快照、同一区间与
排序协议；投影与页长可在续页时修改，坐标锚点不变，因此换投影不会跳过
任何行。分发端不持有 `token_auth_key`，只返回**无 MAC 的令牌体**；客户
验证通过后，用可信根中的密钥在本地附加 HMAC，再保存该签名凭据。

```
continuation_message =
    PROTOCOL_ID || b"|cont|"
    || lp(snapshot_id_utf8)
    || (u32(K) || lp(encode(low_0)) || ...)
    || (u32(K) || lp(encode(high_0)) || ...)
    || (u32(K) || lp(encode(next_key_0)) || ...)
    || i64(next_row_id)

token_mac = HMAC_SHA256(token_auth_key, continuation_message)
```

保存的令牌 JSON 为令牌体加 `token_mac`（hex32）。任何字段（含区间）被
改动、或分发端在没有密钥的情况下自造锚点，都会使 HMAC 校验不一致而被
离线拒绝。验证器还要求令牌锚点与下一页首行的完整坐标精确相等，防止
“锚点落在两行之间”式的漏行。

## 8. 页响应与证明

页 JSON 主要字段：

```
snapshot_id, query(回显原始查询), n_rows, start_pos,
rows[ ]: { pos, key[](wire), row_id, values{投影列: wire} }
predecessor / successor: 相邻位置的 {pos, key, row_id, col_root} 或 null
exhausted: bool
next_continuation: 无 MAC 令牌体（分发端产出）或 null；客户验证后另存
                    带 token_mac 的签名凭据
row_proof:    { n, nodes:[{level,idx,digest}] }
column_proofs: { "<pos>": { open:[叶索引...], nodes:[...] } }
read_counts:  分发端本次真实读取计数（仅供观测，不参与验证）
```

证明节点集合必须恰好等于开放叶子在对应位置化二叉树中的**最小兄弟补集**
（空位可由位置重算，不出现在证明中）。验证器要求：

1. 根凭据 `root_commitment` 重算一致；
2. 页信封的 `snapshot_id`、协议、回显查询与客户输入一致；
3. 行位置连续、严格按完整坐标排序、全部落在 `[low, high)`；
4. 首页起点不低于 `low`；续页首行完整坐标必须与已保存令牌的锚点精确
   相等，且前驱证明锚点与首行之间不存在任何叶子；无密钥自造或篡改的
   令牌在 HMAC 校验阶段即被拒绝；
5. 每个投影值经列树包含证明绑定到正确行的正确列叶；未投影列只出现
   摘要兄弟；
6. 行树包含证明重算根等于可信 `row_tree_root`；证明缺节点、多余未使用
   节点、重复冲突节点、层级/位置错误、摘要长度错误一律拒绝；
7. `exhausted=true` 时后继（若存在）必须在区间外且无令牌；
   `exhausted=false` 时必须有紧邻的区间内后继，令牌坐标与该后继一致，
   且本页恰有 L 行。

## 9. 读取规模

对 N 行、C 列、返回 k 行 m 列的窄页，分发端实际存储读取受

```
O(log N + k · (1 + m · log(C+1)))
```

约束：二分定位 O(log N) 次行叶读取；k 个行叶、k·m 个单元；行树证明
O(log N) 个节点（共享路径自动合并）；每行列树证明 O(m·log(C+1))。
计数器由 SQLite 访问层逐次递增（见 `storage.ReadCounters`），不存在
全表或全列扫描藏在计数之外。
