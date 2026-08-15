# OpenSlay 可验证随机性协议 v2

[English](SPEC.md) | 简体中文

本文规定 `openslay-rng-verify` 对格式版本 2、算法
`openslay-hmac-sha256-state-v2` 执行的公开计算和线格式校验。本文刻意不规定、也不暴露游戏引擎。下文中的“必须”描述的是能获得已验证状态的策牒；明确注明的扩展字段仍可使用。

## 规范值与二进制编码

### 规范 JSON

凡受摘要覆盖的上下文、状态、输入、结果、证明、收据摘要和描述文件载荷，都使用以下规范 JSON 规则：

- 值域仅包括 JSON `null`、布尔值、字符串、整数、数组和对象；不允许浮点值和二进制值。
- 整数限制在可互操作范围 `-(2^53-1)..2^53-1`。布尔值不是整数。
- 字符串由 Unicode 标量值组成，使用不带字节序标记的严格 UTF-8 编码，并且不执行 Unicode 规范化。
- 线格式中的对象键均为字符串。规范序列化会按 Unicode 码点的字典序排序；解析后的线格式对象本身不必已经采用这一顺序。实现若要转换整数映射键，须先将其转换为普通十进制字符串，并拒绝转换后发生的键冲突。
- 序列化不含无意义空白；逗号和冒号分别使用单字节分隔符 `,` 和 `:`，两侧不加空格。
- 整数使用最短十进制写法。字符串按 JSON 要求转义引号、反斜杠及 U+0000 至 U+001F；适用时使用短转义 `\b`、`\t`、`\n`、`\f` 和 `\r`，其余控制字符使用小写 `\u00xx`。正斜杠及其他所有 Unicode 标量值均不转义，直接以 UTF-8 输出。

等价地，对于已经属于上述 JSON 子集的值，在完成上述校验后，参考序列化为 Python
`json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)`。
哈希计算始终先把已解析的值规范化；外层 JSONL 行本身不必按键排序，也不必采用最小空白。

独立加载器在解析 JSONL 和紧凑 JSON 时都会拒绝重复对象键及非有限 JSON 数字词元。有限浮点值是在规范校验遍历受覆盖的随机性内容时被拒绝，而不是由加载器进行全局预检。Godot 内存验证器接收的是已解析值，无法还原重复键或数字词法差异，并会接受该表示中的整数值浮点数。标准 Godot 回放加载器会在调用验证器前，对声称为随机性记录的原始 JSONL 行预检重复键和规范数字词元，从而弥补这一点。绕过该加载器、直接传入已解析字典的调用方不具备同等的原始语法保证；对于不受信任的 JSONL 或紧凑 JSON，严格的独立命令行工具仍是独立校验边界。

### 二进制原语

- `||` 表示原始字节拼接。公式中带引号的域分隔字符串就是所显示的 ASCII 字节，不带长度前缀或终止符。`utf8(value)` 是不带长度前缀的严格 UTF-8。
- `text(value)` 是严格 UTF-8 字节串，并在前面添加其无符号 32 位大端字节长度。
- `uint32_be(value)` 是无符号 32 位大端整数。
- `int64_be(value)` 是有符号 64 位二进制补码大端整数。
- SHA-256 和 HMAC-SHA256 的输出在公式中是原始 32 字节串，在 JSON 中是 64 个小写十六进制字符。参与二进制拼接前，必须先解码十六进制文本。
- `server_secret` 和每个真人玩家的 `client_nonce` 都恰为 32 字节。它们在 JSON 中的表示均为 64 个小写十六进制字符；`server_commitment` 和 `contribution` 亦然。
- 座位编号和 HMAC 块索引位于 `0..2^32-1`；公式编码它们时使用 `uint32_be`。
- `purpose_counter` 是 `0..2^53-1` 范围内的非负规范 JSON 整数；它没有单独的二进制编码。

公开随机输入只移除首尾的 U+0020 SPACE，拒绝 Unicode 通用类别 `Cc` 中的字符，并限制为最多 64 个 UTF-8 字节。协议不对其执行 Unicode 规范化。策牒存储的是已经完成上述规范化的值。

## 对局种子推导

服务器在接受真人玩家贡献之前发布以下承诺：

```text
SHA256(
  "OpenSlay/server-commitment/v1"
  || text(match_id)
  || text(ruleset_hash)
  || server_secret
)
```

`match_id` 是非空字符串。`ruleset_hash` 是 64 个小写十六进制字符组成的 SHA-256 文本。验证器会检查策牒所声明的收据顺序；要证明发布行为确实在当时发生，仍须保留具有可信来源的客户端收据。

真人玩家贡献为：

```text
SHA256(
  "OpenSlay/player-contribution/v1"
  || text(match_id)
  || uint32_be(seat_id)
  || text(public_input)
  || client_nonce
)
```

在线模式主种子按 `seat_id` 升序使用真人玩家贡献；非真人座位不贡献任何字节：

```text
SHA256(
  "OpenSlay/online-master-seed/v1"
  || text(match_id)
  || text(ruleset_hash)
  || server_secret
  || contribution_0 || contribution_1 || ...
)
```

确定性训练模式的主种子为：

```text
SHA256(
  "OpenSlay/training-master-seed/v1"
  || int64_be(numeric_seed)
  || text(public_input)
)
```

`numeric_seed` 位于 `-2^63..2^63-1`。训练模式公开记录把它编码为 JSON **字符串**，内容必须是规范十进制写法：`0`、不带正号和前导零的正十进制数，或 `-` 后接不带前导零的非零十进制数。这样可在不同 JSON 实现间保留完整的有符号 64 位取值域。

## 策牒记录外层

完整对局 JSONL 可以夹杂无关记录。随机性记录是一个外层 JSON 对象，校验规则如下：

| 字段 | 要求 |
| --- | --- |
| `sequence` | 必填的正 JSON 安全整数；随机性记录的值须按文件顺序严格递增，但不必连续。 |
| `record_type` | 值为 `randomness_manifest`、`randomness` 或 `randomness_reveal`；至少须由本字段或 `category` 标识记录。 |
| `category` | `record_type` 的可选别名；若随机性记录带有本字段，它必须与 `record_type` 或据以识别的类型相同。 |
| `format_version` | 外层可选；若存在，必须是 JSON 整数 `2`。 |
| `context` | 必填对象，包含下文规定的内层记录。 |

其他外层字段（如 `created_at` 和 `message`）可以存在；密码学验证会忽略它们，审计哈希也不覆盖它们。符合规范的生成方应同时输出值相同的 `record_type` 与 `category`，并输出外层 `format_version = 2`。任一类型字段中以 `randomness` 开头的未知字符串均为无效记录，不能忽略。

一旦出现任何可识别的 v2 随机性记录，策牒就必须恰有一条清单记录；它须位于所有操作和公开记录之前；公开记录最多一条。操作顺序就是 `randomness` 记录的文件顺序。公开记录的外层 `sequence` 须晚于清单和所有操作。缺少公开记录的策牒为 `Incomplete`；操作或公开记录没有对应清单则为 `Invalid`。其他方面有效但不含任何可识别 v2 随机性记录的输入视为旧式仅种子日志，并返回 `Unverified`。

## 清单上下文

`randomness_manifest` 上下文包含下列公共字段。表中公共字段及各模式专属字段凡注明必填者均须存在。可以添加其他规范扩展字段，且它们会进入清单审计哈希。

| 字段 | 要求 |
| --- | --- |
| `format_version` | JSON 整数 `2` |
| `algorithm` | `openslay-hmac-sha256-state-v2` |
| `mode` | `training`、`online`，或明确不作验证的兼容值 `unverified` |
| `ruleset_hash` | 64 个小写十六进制字符组成的摘要 |
| `match_id` | `training` 和 `online` 模式下为非空字符串 |
| `commitment_published_order` | 训练模式为 `null`；在线模式为非负 JSON 安全整数 |
| `participants` | 训练模式为空数组；在线模式为按座位升序排列的收据数组 |
| `server_commitment` | 训练模式为 `null`；在线模式为 64 个小写十六进制字符组成的摘要 |
| `deck_source` | 若要获得已验证结果，必须是 `oracle`；缺失或取其他值会在完成其他所有适用检查后得到 `Unverified`。 |

`public_rules_hash` 可作为扩展字段存在；其独立的规则层语义见[公开规则](#公开规则)。

在兼容模式 `unverified` 下，验证器只要求 `format_version`、`algorithm`、`mode` 和 `ruleset_hash`；其他清单字段是没有已验证推导语义的规范扩展。

### 在线参与者收据

符合规范的生成方为每位参与者恰好输出以下七个字段。下列尖括号字符串是模式元变量，不是线格式中的字面值：

```json
{
  "seat_id": 1,
  "driver_kind": "human",
  "public_randomness_input": "42",
  "client_nonce": "<64 个小写十六进制字符>",
  "contribution": "<64 个小写十六进制字符>",
  "commitment_received_order": 1,
  "accepted_order": 2
}
```

`seat_id` 是互不重复的 uint32 整数，参与者数组按座位升序排列。`driver_kind` 是非空字符串。当
`driver_kind = "human"` 时，余下五个字段均为必填：公开输入须已规范化；随机数和贡献均须是表示 32 字节的小写十六进制值；两个顺序字段均为正 JSON 安全整数；须满足
`commitment_received_order < accepted_order`，且二者都大于清单的
`commitment_published_order`。所有真人玩家的收据顺序值和接受顺序值在全局范围内均不得重复。验证器会重新计算每个真人玩家的贡献。

对于其他任何 `driver_kind`，该座位为非真人座位，五个可选字段都必须为 JSON `null`（验证器也接受省略这些字段作为等价的紧凑形式）。非真人座位不参与主种子推导。

## 操作上下文与状态绑定

每个 `randomness` 上下文**恰好**包含以下字段；缺失或增加字段均为无效：

```text
format_version, algorithm, operation_sequence, operation, purpose,
purpose_counter, scope, inputs, state, state_digest, context_digest,
result, proof, previous_audit_hash, audit_hash
```

公共约束如下：

- `format_version` 是 JSON 整数 `2`，`algorithm` 是 `openslay-hmac-sha256-state-v2`。
- `operation_sequence` 是从 1 开始、正数、全局无间隔的操作索引。每个用途各自的 `purpose_counter` 从 0 开始，并按文件顺序无间隔递增。
- `purpose` 是 2 至 128 个 ASCII 字符，并匹配 `[a-z0-9][a-z0-9._:/-]{1,127}`。
- `previous_audit_hash`、`state_digest`、`context_digest` 和 `audit_hash` 均为 64 个小写十六进制字符。
- `operation` 是 `probability`、`choice`、`sample` 或 `shuffle`；其 `inputs`、`result` 和 `proof` 必须严格符合下文语义。

`scope` 恰好包含以下字段：

| 字段 | 类型与约束 |
| --- | --- |
| `scope_id` | 非空字符串 |
| `parent_scope_id`、`event_id`、`event`、`phase`、`skill` | 字符串或 `null` |
| `round` | 非负 JSON 安全整数 |
| `owner`、`actor` | JSON 安全整数或 `null` |
| `targets` | JSON 安全整数数组 |

随机操作前，引擎记录规范的权威 `state` 对象。符合规范的状态具有 JSON 整数
`state_version = 1` 和非空字符串 `kind`；可以添加其他规范字段。OpenSlay 引擎状态包含隐藏牌区和当前结算状态，不是面向某位玩家删减信息后的界面快照。验证器只校验规范形式、`state_version`、`kind` 和摘要；它不证明状态完整，也不证明该状态是前一状态的合法转换。

状态与操作上下文按以下方式绑定：

```text
state_digest = SHA256(
  "OpenSlay/random-state/v1"
  || utf8(canonical_json(authoritative_pre_operation_state))
)

context_digest = SHA256(
  "OpenSlay/random-context/v1"
  || utf8(canonical_json({
       format_version, algorithm, operation_sequence,
       operation, purpose, purpose_counter, scope, inputs,
       state_digest, previous_audit_hash
     }))
)
```

## HMAC 流与有界抽取

一次语义操作从以下计算获得 256 位数据块：

```text
HMAC-SHA256(
  key=master_seed,
  message="OpenSlay/random-stream/v2"
          || bytes.fromhex(context_digest)
          || uint32_be(block_index)
)
```

每次操作内的 `block_index` 从零开始，每次尝试后递增，包括被拒绝的值；它不得回绕。把 32 个 HMAC 字节解释为一个无符号**大端**整数 `value`。对于满足
`1 <= b <= 2^256` 的上界 `b`，令：

```text
limit = 2^256 - (2^256 mod b)
```

拒绝 `>= limit` 的值；接受第一个小于 `limit` 的值，并返回 `value mod b`。每次有界抽取具有以下严格字段布局：

```json
{
  "upper_bound": 7,
  "block_index": 1,
  "raw_value": "0000000000000000000000000000000000000000000000000000000000000002",
  "rejected": [
    {"block_index": 0, "raw_value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
  ]
}
```

示例字段值仅用于说明：`block_index` 指向被接受的块，`rejected` 按顺序列出本次抽取在它之前被拒绝的所有块，因此不得再次包含已接受索引。`raw_value` 是 32 个 HMAC 字节直接写成的小写十六进制。有效语义操作策牒中出现的所有上界本身也必须能以规范 JSON 表示。

## 语义操作与证明布局

候选值可以是任意规范 JSON 值，也可以重复。每个证明对象都恰好包含示例所示的字段。`blocks_used` 是所有抽取完成后操作流的下一个块索引，即该操作消耗的已接受块与被拒绝块总数。以下示例是布局示意；其中的十六进制值用于展示必要结构和运算，但并不声称是在未给出种子及上下文时实际得到的 HMAC 输出。

### `probability`

输入恰好包含 `numerator` 和 `denominator`，二者均为 JSON 整数，并满足
`0 <= numerator <= denominator <= 2^53-1` 且 `denominator > 0`。在
`[0, denominator)` 内抽取 `d`，返回 `d < numerator`。

以下示意输入为 `{"numerator":3,"denominator":7}`：

```json
{
  "result": true,
  "proof": {
    "draw": 2,
    "draws": [{"upper_bound": 7, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000002", "rejected": []}],
    "blocks_used": 1
  }
}
```

### `choice`

输入恰好包含非空数组 `candidates`。在 `[0, len(candidates))` 中抽取一个索引；结果是该索引处的候选值。

以下示意输入为 `{"candidates":["first","second","third"]}`：

```json
{
  "result": "second",
  "proof": {
    "selected_index": 1,
    "draws": [{"upper_bound": 3, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000001", "rejected": []}],
    "blocks_used": 1
  }
}
```

### `sample`

输入恰好包含数组 `candidates` 和 JSON 整数 `count`，并满足
`0 <= count <= len(candidates)`。从剩余原始索引 `[0, ..., n-1]` 开始；反复抽取该剩余列表中的相对索引，将其移除，并把被移除的原始索引追加到
`selected_indices`。结果是按选择顺序排列的这些原始索引所对应的候选值。

以下示意输入为
`{"candidates":["first","second","third"],"count":2}`：

```json
{
  "result": ["third", "first"],
  "proof": {
    "selected_indices": [2, 0],
    "draws": [
      {"upper_bound": 3, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000002", "rejected": []},
      {"upper_bound": 2, "block_index": 1, "raw_value": "0000000000000000000000000000000000000000000000000000000000000000", "rejected": []}
    ],
    "blocks_used": 2
  }
}
```

当 `count = 0` 时，三个数组都为空，且 `blocks_used = 0`。

### `shuffle`

输入包含 `candidates`，并可选包含对象 `metadata`；不得有其他字段。允许候选数组为空。初始化
`permutation = [0, ..., n-1]`。令 `i` 从 `n-1` 递减到 `1`；在
`[0, i]` 中抽取 `j`，交换 `permutation[i]` 与 `permutation[j]`，并把
`[i,j]` 追加到 `swaps`。结果是按最终排列顺序取得的原候选值。

以下示意输入为 `{"candidates":["first","second","third"]}`：

```json
{
  "result": ["third", "first", "second"],
  "proof": {
    "permutation": [2, 0, 1],
    "swaps": [[2, 1], [1, 0]],
    "draws": [
      {"upper_bound": 3, "block_index": 0, "raw_value": "0000000000000000000000000000000000000000000000000000000000000001", "rejected": []},
      {"upper_bound": 2, "block_index": 1, "raw_value": "0000000000000000000000000000000000000000000000000000000000000000", "rejected": []}
    ],
    "blocks_used": 2
  }
}
```

当候选值数量为零或一时，`swaps` 和 `draws` 为空，
`permutation` 是恒等列表，且 `blocks_used = 0`。

### 原型牌堆纪元

当记录的用途以 `deck.epoch.` 开头，或其洗牌元数据包含 `deck_epoch` 时，该记录声称自己是牌堆纪元；此时两种声明都必须存在且一致。它必须是 `shuffle`，用途必须恰为
`deck.epoch.N`，其中 `N` 从 1 开始逐一递增。元数据恰好包含：

```json
{"deck_epoch": 1, "start_card_id": 1, "card_count": 144}
```

`start_card_id` 从 1 开始，每个纪元增加 144；`card_count` 等于候选值数量。每个纪元都按权威的洗牌前顺序包含随包提供的 144 张原型牌，并使用连续的运行时
`card_id`。把这些 ID 替换为 `1..144` 后，
`SHA256(utf8(canonical_json(candidates)))` 为
`8f4503267ca0c9d2fe0a8835121ab2cc9c4b79165ea64641f562f15a8c6ffc39`。完整公开候选列表随包提供，路径为 `data/prototype-deck-v1.json`。

## 策牒哈希链

每条随机性记录都在前一个哈希上继续延伸：

```text
SHA256(
  "OpenSlay/random-audit-chain/v1"
  || bytes.fromhex(previous_hash)
  || utf8(canonical_json({"record_type": type, "context": context}))
)
```

清单从 32 个零字节开始，其完整上下文（包括扩展字段）都参与哈希。操作记录套用公式前，从上下文移除 `previous_audit_hash` 与 `audit_hash`；公式的第一个参数是该记录所声明的上一链头；结果存入 `audit_hash`。公开记录只移除
`final_audit_hash`；结果存入 `final_audit_hash`。因此，完整公开上下文会绑定已公开的种子材料、结果、收据摘要、操作数量和扩展字段。

每条操作记录都存储完整规范 `state`、`state_digest` 和 `context_digest`。验证会重新计算两个摘要、每个 HMAC 块、结果、完整证明对象及每个审计链头。实时检查点不含原始隐藏状态字段，但其链头摘要覆盖含状态的记录；本文不证明无法从这些链头推断语义信息。

## 公开上下文与就绪收据

每个 `randomness_reveal` 上下文使用以下公共字段；除表中注明可选者外均为必填。可以添加其他规范扩展字段，且它们会进入 `final_audit_hash`。

| 字段 | 要求 |
| --- | --- |
| `format_version` | JSON 整数 `2` |
| `algorithm` | `openslay-hmac-sha256-state-v2` |
| `mode` | 与清单模式完全相同 |
| `outcome` | `completed` 或 `aborted` |
| `reason` | 可选；若存在，须为字符串或 `null` |
| `operation_count` | 非负 JSON 安全整数，且等于操作记录数量 |
| `receipt_summary` | 对象；模式专属要求见下文 |
| `final_audit_hash` | 64 个小写十六进制字符组成的公开记录链头 |

### 训练模式公开记录

公开上下文还必须包含 `numeric_seed`（规范的有符号 64 位十进制**字符串**）和已规范化的字符串 `public_randomness_input`。不得包含 `server_secret`。
`receipt_summary` 必须是对象，但版本 2 不要求任何训练模式摘要键；`{}` 有效，任何规范扩展字段都会受哈希绑定。

### 在线模式公开记录

公开上下文还必须包含 `server_secret`，其为恰好表示 32 字节的小写十六进制。不得包含 `numeric_seed` 或 `public_randomness_input`。`receipt_summary` 至少包含以下字段；可以增加其他规范字段，且它们受哈希绑定：

| 字段 | 要求 |
| --- | --- |
| `match_id` | 与清单 `match_id` 完全相同 |
| `winner_ids` | 元素为 uint32 玩家 ID 的数组；版本 2 不要求排序或唯一 |
| `required_seats` | 开局前要求到齐的真人座位，按升序排列且不重复的 uint32 数组 |
| `accepted_seats` | 按升序排列且不重复的 `required_seats` 子集 |
| `start_delivered_seats` | 按升序排列且不重复，并同时为 `required_seats` 与 `accepted_seats` 子集 |
| `contributions_complete` | 布尔值，且等于 `(accepted_seats == required_seats)` |

清单参与者收据中的真人座位升序列表必须等于 `accepted_seats`。仅当
`contributions_complete` 为真且 `start_delivered_seats == required_seats` 时，就绪状态才完整。

如果就绪状态不完整，`outcome` 必须为 `aborted`。这种策牒只有在不含任何随机操作并声明 `operation_count = 0` 时才是 `Incomplete`；就绪状态不完整却包含操作的策牒是 `Invalid`。就绪状态完整时，两种终局结果都允许——随机性验证器不认证对局是否完成。

### 未验证兼容模式公开记录

`unverified` 模式不增加推导专属的公开字段。公共字段、规范形式、记录顺序和审计链仍为必需；其他规范字段是扩展。如下文所述，验证器会在重建收据、种子、HMAC 结果或牌堆纪元之前返回。

## 验证完成语义

验证按以下分支完成：

- 模式 `unverified` 在完成规范结构、顺序、摘要、审计链和公开记录检查后得到
  `Unverified`；这一兼容分支不会重建收据或种子，也不会重算 HMAC 结果或牌堆纪元。
- 在 `training` 或 `online` 模式下，完成收据、种子和操作重算后，若清单
  `deck_source` 不是 `oracle`，或清单、任一操作上下文或公开上下文中的任意规范字段名为 `unverified_adapter`，结果为 `Unverified`，而不是已验证声明。
- 已验证策牒必须包含至少一个有效的原型牌堆纪元。中止的策牒若没有纪元则为
  `Incomplete`；完成且使用 oracle 牌堆的策牒若没有纪元则为 `Invalid`。
- 成功的在线模式策牒为 `Verified fair`；成功的训练模式策牒为
  `Verified deterministic`。这些名称只表明本文规定的内部协议一致性，不保证熵质量、服务器诚实、游戏状态转换合法或对局完成。

## 行动树性质

状态绑定消除了“同一用途第 N 次使用永远消耗同一随机值”的固定时间表。在不存在 SHA-256 碰撞的假设下，当已接受行动产生不同的已记录操作前状态或上下文时，其后续使用不同的 HMAC 消息；若多个行动收敛到同一份已记录绑定，其后续不一定分叉。如果决策点 `t` 有 `b_t` 个合法分支，深度为
`T` 的行动树大约可有 `b_1 * b_2 * ... * b_T` 个叶节点。每回合摸两张牌会持续改变手牌、时机、目标、响应和组合选择，因此真人控制的分支通常呈指数增长。

这会为开局前搜索有利种子制造计算障碍，但不能证明权威服务器绝对无法预测结果。知道主种子的服务器可以计算任何完全给定的假想状态，并可能搜索或剪枝行动树。服务器若知道机器人策略和策略随机源，机器人座位便不提供独立熵。因此，在线推导要求开局前服务器承诺，并要求每个真人座位提供贡献；全机器人在线对局只依赖已承诺的服务器秘密，训练模式则是确定性的。策牒强制随机操作顺序无间隔并要求终局公开。要阻止行动研磨，游戏集成还须维持已接受行动的单调顺序，并禁止接受后回滚或重掷；独立验证器没有已接受行动日志，无法认证这些要求。

独立密码学验证器能证明某个结果由记录的状态和主种子产生。若要证明相邻状态是合法游戏转换，还必须根据已接受行动日志回放确定性引擎。实时检查点链头可让客户端发现其保留前缀被替换；它不能阻止另一条未见后缀或分叉视图。声明的收据顺序编号同样不是时间戳，也不是第三方签名收据。

## 本机见证

客户端首先写入 `witness_header`，随后在显示声称使用了新检查点链头的状态之前，为每次随机操作刷新一条 `randomness_checkpoint`。见证格式版本 1 拒绝缺失或额外字段。头记录具有 `record_type = "witness_header"`、JSON 整数 `format_version = 1`、已验证清单中的非空 `match_id`，且模式为 `training` 或 `online`。它恰好包含这四个字段，并在训练模式下增加 `numeric_seed` 与 `public_randomness_input`，或在在线模式下增加
`ruleset_hash`、`server_commitment`、`seat_id`、`public_randomness_input`、
`client_nonce` 和 `contribution`。训练模式的种子与公开输入均为字符串并等于已验证公开记录，因此种子使用同一规范十进制字符串。在线模式的 `ruleset_hash` 与 `server_commitment` 等于已验证清单；`seat_id` 是 uint32 并标识其中的真人参与者；三个参与者字符串等于该收据。每个检查点恰好包含：

- `record_type` = `randomness_checkpoint`
- `format_version` = 1
- `match_id`
- JSONL `log_sequence`
- `operation_sequence`
- `previous_audit_hash`
- `audit_hash`

操作序号从 1 开始且无间隔；日志序号为正 JSON 安全整数并严格递增。哈希均为 64 个小写十六进制字符；第一条之后的每个检查点都须把前一检查点的
`audit_hash` 作为自己的上一链头。

`Complete` 见证结果要求终局策牒本身已通过验证，且检查点须按顺序与其中操作一一对应。头记录还会与已验证的清单、公开记录及参与者收据交叉核对；每个检查点的相等性覆盖 `match_id`、外层 `log_sequence`、`operation_sequence`、`previous_audit_hash` 和 `audit_hash`。这只证明所提供检查点与策牒相等。若要把检查点解释为对局过程中保存的记录，还需要可信且不可改写的本机来源；它们不是第三方时间戳或公共公证。赛后重建的附属文件也能通过数据校验，但不能证明曾进行实时观察。界面显示的五组短印只是 256 位终局审计哈希的前 80 位：它仅用于人工发现不一致，短印相同不能证明完整哈希相同。

## 公开规则

密码学验证器证明报告的结果来自记录的输入。可选 JSON 规则描述文件还可利用公开卡牌和技能说明约束这些输入。描述文件是数据，不是引擎源码。其可复现哈希为：

```text
SHA256("OpenSlay/public-rules/v1" || utf8(canonical_json(descriptor_without_hash)))
```

版本 2 游戏策牒不强制要求 `public_rules_hash`。当提供描述文件、规则检查通过且清单包含匹配字段时，该字段会在 SHA-256 碰撞抗性假设下，以计算方式把解析后的规范描述载荷（不含 `public_rules_hash` 字段本身）绑定到所提供的策牒。描述文件自身哈希不能单独提供策牒绑定或开局收据前绑定；若描述文件未经过外部认证，其中的
`compatible_ruleset_hashes` 也只是描述文件自身提出的兼容性声明。
