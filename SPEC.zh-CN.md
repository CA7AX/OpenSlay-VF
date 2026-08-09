# OpenSlay 可验证随机性协议 v2

[English](SPEC.md) | 简体中文

本文规定 `openslay-rng-verifier` 执行的公开计算。本文刻意不规定、也不暴露游戏引擎实现。

## 二进制编码

- 文本使用严格 UTF-8 编码，并在前面添加一个无符号 32 位大端字节长度。
- 训练种子编码为有符号 64 位大端整数。
- 座位编号和 HMAC 块索引编码为无符号 32 位大端整数。
- `purpose_counter` 是 `0..2^53-1` JSON 安全范围内的非负规范 JSON 整数；
  它没有单独的二进制编码。
- 摘要在内部为 32 字节，在 JSON 中为 64 个小写十六进制字符。

公开随机输入只移除首尾的 U+0020 SPACE，拒绝 Unicode 控制字符，并限制为最多 64 个 UTF-8 字节。协议不对其执行 Unicode 规范化。

## 对局种子推导

服务器必须在接受真人玩家贡献之前发布以下承诺：

```text
SHA256(
  "OpenSlay/server-commitment/v1"
  || text(match_id)
  || text(ruleset_hash)
  || server_secret
)
```

真人玩家贡献的计算方式为：

```text
SHA256(
  "OpenSlay/player-contribution/v1"
  || text(match_id)
  || uint32_be(seat_id)
  || text(public_input)
  || client_nonce
)
```

在线模式主种子按座位编号升序拼接真人玩家贡献：

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

## 与状态绑定的操作流

某一用途第一次使用时 `purpose_counter = 0`，第二次为 1，以此类推。每一种用途拥有独立计数器。执行随机操作前，引擎记录一个规范的权威状态对象，其中 `state_version = 1` 且 `kind` 非空。该状态包含隐藏牌区和正在处理的结算状态，并不是为某位玩家删减信息后的界面快照。

状态与操作上下文按以下方式绑定：

```text
state_digest = SHA256(
  "OpenSlay/random-state/v1"
  || canonical_json(authoritative_pre_operation_state)
)

context_digest = SHA256(
  "OpenSlay/random-context/v1"
  || canonical_json({
       format_version, algorithm, operation_sequence,
       operation, purpose, purpose_counter, scope, inputs,
       state_digest, previous_audit_hash
     })
)
```

一次语义随机操作随后从以下计算获得 256 位数据块：

```text
HMAC-SHA256(
  key=master_seed,
  message="OpenSlay/random-stream/v2"
          || bytes.fromhex(context_digest)
          || uint32_be(block_index)
)
```

每次操作内部的 `block_index` 从零开始。有界整数使用拒绝采样：只有当 256 位值小于 `2^256 - (2^256 mod bound)` 时才接受，然后返回 `value mod bound`。

- `probability`：在 `[0, denominator)` 中取值，并判断 `draw < numerator`。
- `choice`：从记录的候选列表中抽取一个索引。
- `sample`：反复从剩余索引中抽取并移除一个索引。
- `shuffle`：执行从后向前的 Fisher–Yates 交换。

当前原型规则集规定，每个权威牌堆纪元必须包含 144 张牌。把其连续运行时 `card_id` 替换为 `1..144` 后，候选列表规范 JSON 的 SHA-256 必须等于 `8f4503267ca0c9d2fe0a8835121ab2cc9c4b79165ea64641f562f15a8c6ffc39`。完整公开候选列表随包提供，路径为 `data/prototype-deck-v1.json`。

## 策牒哈希链

规范 JSON 使用 UTF-8、按对象键排序、不含无意义空白、不允许浮点数，并将整数限制在 JSON 安全范围内。
独立 Python JSONL 加载器会在解析时拒绝重复对象键。浮点值是在规范验证遍历受覆盖的随机记录内容时被拒绝，而不是由加载器全局预检。Godot 界面会先让引擎解析器处理原始 JSON；在客户端验证器看到数据之前，该解析器可能已经折叠重复键，并规范化数值为整数的浮点词法。因此，不受信任的原始策牒必须交给严格的独立命令行验证器；客户端结果在这一原始语法边界上并不等价。

每一条带类型的记录都在前一个哈希上继续延伸：

```text
SHA256(
  "OpenSlay/random-audit-chain/v1"
  || bytes.fromhex(previous_hash)
  || utf8(canonical_json({"record_type": type, "context": context}))
)
```

清单记录从 32 个零字节开始。计算操作记录时，从传入上述公式的上下文中排除 `previous_audit_hash` 和 `audit_hash`；计算公开记录时排除 `final_audit_hash`。

每条操作记录都包含完整规范的 `state`、`state_digest` 和 `context_digest`。验证时先重新计算两个摘要，再重新计算 HMAC 结果。实时检查点不含原始隐藏状态字段，但其链头摘要覆盖含状态的记录；本文未证明无法从这些链头推断语义信息。

## 行动树性质

状态绑定消除了“同一用途第 N 次使用永远消耗同一随机值”的固定时间表。当已接受行动产生不同的已记录操作前状态或上下文时，其后续随机流也不同；若多个分支收敛到同一份绑定记录，则随机流不一定分叉。如果决策点 `t` 有 `b_t` 个合法分支，深度为 `T` 的行动树大约可以包含 `b_1 * b_2 * ... * b_T` 个叶节点。每回合摸两张牌会持续改变手牌、时机、目标、响应和组合选择，因此真人控制的分支通常呈指数增长。

这会为开局前搜索有利种子制造计算障碍，但不能证明权威服务器绝对无法预测结果。知道主种子的服务器可以计算任何完全给定的假想状态，并可能搜索或剪枝行动树。服务器若知道机器人策略和策略随机源，机器人座位便不能提供独立熵。因此协议还要求开局前承诺、真人玩家贡献、单调递增的行动及操作顺序、行动被接受后不得回滚或重掷，以及终局公开材料。

可独立运行的密码学验证器能够证明某个结果确实由记录的状态和主种子产生。若要证明相邻状态之间是合法的游戏状态转换，还必须根据已接受的行动日志对确定性引擎进行回放。实时检查点链头可让客户端发现其已保存前缀被替换；它不能阻止另一条未见后缀或分叉视图。

## 本机见证

客户端首先写入 `witness_header`，随后在显示声称使用了新链头的状态之前，为每次随机操作刷新一条 `randomness_checkpoint`。格式版本 1 拒绝缺失或额外字段。头记录仅包含 `record_type`、`format_version`、`match_id`、`mode`，以及训练模式的 `numeric_seed`、`public_randomness_input`，或在线模式的 `ruleset_hash`、`server_commitment`、`seat_id`、`public_randomness_input`、`client_nonce`、`contribution`。每个检查点仅包含：

- `record_type`
- `format_version`
- `match_id`
- JSONL `log_sequence`
- `operation_sequence`
- `previous_audit_hash`
- `audit_hash`

终局验证要求每个检查点都与终局策牒中的对应操作完全一致。这只证明终局记录与所提供检查点相等。若要把检查点解释为游戏过程中保存的记录，还需要可信且不可改写的本机来源；它们不是第三方时间戳或公共公证服务。

## 公开规则

密码学验证器证明报告的结果来自记录的输入。可选的 JSON 规则描述文件还可以利用公开卡牌和技能说明约束这些输入。描述文件只是数据，并非引擎源码。其可复现哈希为：

```text
SHA256("OpenSlay/public-rules/v1" || canonical_json(descriptor_without_hash))
```

版本 2 游戏策牒暂不强制要求 `public_rules_hash`。当提供描述文件、规则检查通过，且清单包含匹配的该字段时，该字段会在 SHA-256 碰撞抗性假设下，以计算方式把解析后的规范描述文件载荷（不含 `public_rules_hash` 字段本身）绑定到所提供的策牒中。描述文件自身的哈希不能单独提供策牒绑定或开局收据前绑定；若描述文件未经过外部认证，其中的 `compatible_ruleset_hashes` 也只是描述文件自身提出的兼容性声明。
