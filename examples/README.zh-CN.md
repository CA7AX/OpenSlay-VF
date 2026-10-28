# 示例策牒：一份真实，一份伪造

[English](README.md)

本目录收录同一局 OpenSlay 对局的两份随机性策牒。一份与游戏写出的内容完全相同；另一份是精心伪造的副本：它翻转了一次不影响对局结果的掷骰，并把不需要种子就能修补的地方全部修补好。本指南说明如何验证这两份策牒，以及验证器为何仍能识破这份伪造。

| 文件 | 内容 | 预期状态 | 退出码 |
| --- | --- | --- | ---: |
| [`training-2v2-seed42.valid.json`](training-2v2-seed42.valid.json) | 原样记录的策牒 | `Verified deterministic`（定策可验） | `0` |
| [`training-2v2-seed42.tampered-careful.json`](training-2v2-seed42.tampered-careful.json) | 翻转最后一次掷骰，并相应修补证明、牌堆账册和哈希 | 序号 `582` 处 `Invalid`（无效） | `1` |

## 对局来源

这是一局合成对局：四个规则机器人进行 2v2 训练对局（貂蝉、太史慈对庞统、孙权），数值种子为 `42`，公开随机输入为 `雪`。没有真人参与。蓝方（庞统、孙权）获胜。

两个文件都是紧凑策牒：一个 JSON 对象，其 `records` 列表只保留游戏日志中的随机性记录，即 1 条 `randomness_manifest`、22 次 `randomness` 操作和 1 条 `randomness_reveal`。每条记录的 `sequence` 是它在原始游戏日志中的行号，因此编号并不连续。每次操作都保留了它所绑定的引擎状态，所以文件较大（各约 740 KB）。这些记录采用 2026-10 平衡调整后的概率，因此对照随包的 `openslay-prototype-v3` 规则核验。

训练策牒会公开种子，任何人都能重算每一次掷骰。因此它证明的是策牒内部一致、可以复现，而不能证明服务器诚实；联机协议另外用承诺和玩家随机数来解决这一点。参见[验证不能证明的内容](../README.zh-CN.md)。

## 这份伪造

伪造者只翻转了一次掷骰。选中的这次掷骰翻转之后，策牒的其余部分仍能自圆其说；翻转所波及的每个值也都修补好了。如果只改结果，这条记录的审计哈希就会对不上，而这不需要种子就能查出。

**为什么选最后一次掷骰。** 每次掷骰的 HMAC 块都由上下文摘要决定，而上下文摘要覆盖前一条记录的审计哈希。因此改动任何一次掷骰，都会改变其后每次掷骰的 HMAC 块。记录 `582` 是 22 次掷骰中的最后一次，其后只有公开记录。

**为什么选这次掷骰。** 第 22 轮，孙权的技能「江左雄略」以 1/2 的概率多摸一张牌。掷骰成功，他摸到第 100 号牌（摧锋♣），但始终没有打出。他用掷骰之前刚摸到的杀♦击杀貂蝉，对局就此结束。即使掷骰失败，蓝方也会在同一回合、用同一张杀获胜。我们把这次掷骰强制改为失败后重跑了这局对局：战报只少了一行 `[孙权] 摸了1张牌`，其余完全相同。

**改了什么。** 与真实文件相比，共有七个值不同：

| 字段 | 真实策牒 | 伪造 | 原因 |
| --- | --- | --- | --- |
| 掷骰 `result` | `true` | `false` | 翻转本身 |
| 掷骰 `proof.draw` | `0` | `1` | 与新结果一致 |
| 掷骰 `proof.draws[0].raw_value` | `…4228ee` | `…4228ef` | 奇数块的抽值为 `1` |
| 掷骰 `audit_hash` | `5fb9d140…` | `25c5f087…` | 重新计算 |
| 公开记录 `sequence` | `596` | `593` | 这次摸牌的三行日志不复存在 |
| 公开记录 `deck_ledger_tail` | 孙权摸第 100 号牌 | 空 | 掷骰失败就不摸牌 |
| 公开记录 `final_audit_hash` | `09bee980…` | `31390c5c…` | 重新计算 |

哈希函数是公开的，任何人都能重算这两个哈希。上述强制失败的重跑逐字节生成了这份文件：假如那一个 HMAC 块是奇数，游戏记录下来的就是它。[`tests/test_examples.py`](../tests/test_examples.py) 会按上表的改动，从真实文件重建它。

伪造者没有改动这次掷骰的状态和范围，所以它的上下文摘要不变。正是这一点暴露了伪造（见第 5 步）。

## 亲手验证

### 1. 安装

需要 Python 3.10 或更高版本，无其他依赖。

```bash
git clone https://github.com/CA7AX/OpenSlay-VF.git
cd OpenSlay-VF
python -m pip install -e .
```

以下命令均在仓库根目录运行。

### 2. 查看改了什么

```bash
diff examples/training-2v2-seed42.valid.json examples/training-2v2-seed42.tampered-careful.json
```

diff 会列出上表中的七处改动。Windows 上可用 `fc` 代替 `diff`。

### 3. 验证真实策牒

```bash
openslay-rng-verify examples/training-2v2-seed42.valid.json --rules bundled --language zh
```

```text
验证状态: 定策可验
摘要: 定策可验：已核验 22 次随机操作、1 个牌堆纪元和 59 次牌堆动作。
随机操作数: 22
已验证牌堆纪元: 1
已验证牌堆动作: 59
终局审计哈希: 09bee98039744b8a1d4a3c4dbf146a88e5f86818428e86d64e7a2eb0017ed5a9

公开规则: 已验证
摘要: 全部 22 次随机操作均符合公开规则描述。
```

本指南中的示例输出省略了报告标题、策牒路径和规则细节行。

退出码为 `0`。验证器用 `42` 和 `雪` 重建训练主种子，重算全部 22 次操作（包括 144 张牌的洗牌），并按该洗牌结果重放全部 59 次摸牌；它还重建了直到终局审计哈希的哈希链，并用公开规则核对每次操作的输入。

### 4. 验证伪造策牒

```bash
openslay-rng-verify examples/training-2v2-seed42.tampered-careful.json --rules bundled --language zh
```

```text
验证状态: 无效
摘要: 随机性策牒无效。 技术原因（英文原文）：Invalid randomness transcript at JSONL sequence 582 (skill.wu.sun-quan.draw-phase.flood-extra-card): result does not match the HMAC-derived operation
随机操作数: 21
已验证牌堆纪元: 1
已验证牌堆动作: 56
失败记录序号: 582
失败随机操作: 22
失败用途: skill.wu.sun-quan.draw-phase.flood-extra-card
终局审计哈希: 31390c5cb0828586d2dca21f268a18875fe3ac1a8ec9b1307ceff97e35eb051a

公开规则: 无效
摘要: 策牒验证失败，因此不能信任其中声明的规则输入。
```

退出码为 `1`。报告准确指出被改动的记录、操作和用途。这份文件通过了所有不需要种子的检查：每条记录的结构和摘要、审计哈希链，以及公开记录的终局哈希。随后验证器推导种子，依次重算每次掷骰。前 21 次掷骰和 56 次牌堆动作都相符；第 22 次不符，因为在这个上下文下，种子给出的 HMAC 块与伪造者存进去的不同。规则检查也随之失败，因为来自已损坏策牒的规则输入不可信。

`终局审计哈希` 一行显示的是伪造的公开记录所声称的哈希。它与真实的 `09bee980…` 不同，所以保存了对局结束时显示的哈希的人，不用运行验证器也能发现改动。

去掉 `--language` 即得到默认的中英双语报告；加上 `--json` 可得到稳定的机器可读报告：

```bash
openslay-rng-verify examples/training-2v2-seed42.tampered-careful.json --json
```

JSON 报告的 `verification` 中包含 `"status": "Invalid"`、`"failure_sequence": 582` 和 `"exit_code": 1`。

### 5. 手动重算这次掷骰

不必只听验证器的。下面的脚本只用公开协议原语，从公开的种子重算记录 582：

```python
import json
from openslay_rng_verifier.protocol import HMACStream, derive_training_master_seed

with open("examples/training-2v2-seed42.tampered-careful.json", encoding="utf-8") as handle:
    records = json.load(handle)["records"]
reveal = records[-1]["context"]
roll = next(r["context"] for r in records if r["sequence"] == 582)

seed = derive_training_master_seed(
    int(reveal["numeric_seed"]), reveal["public_randomness_input"]
)
stream = HMACStream(seed, context_digest=bytes.fromhex(roll["context_digest"]))
draw, proof = stream.bounded(roll["inputs"]["denominator"])

print("recorded:", roll["result"])                        # False（伪造）
print("recomputed:", draw < roll["inputs"]["numerator"])  # True
print("same HMAC block:", proof["raw_value"] == roll["proof"]["draws"][0]["raw_value"])  # False
```

记录的结果与存储的块一致，但存储的块并不是种子在这个上下文下给出的那个。真实的块以 `…ee` 结尾，是偶数，所以抽值为 `0`。抽值小于 `numerator = 1` 时掷骰成功，所以它其实成功了。

完整验证器还会从规范化的范围、状态、输入和前一条审计哈希重算 `context_digest`，伪造者无法另选上下文来换一个“幸运”的块。

## 修补伪造需要付出什么

- **改写哈希和存储的块。** 这份伪造两样都做了，重算的掷骰照样揭穿了它。
- **更换种子。** 每次操作、牌堆顺序和全部 59 次牌堆动作都会随之改变。那是另一局对局，而不是对这一局的小改动。
- **改动记录的状态或范围，直到 HMAC 块给出想要的结果。** 掷骰绑定在状态上，所以这需要换一个状态。验证器会用牌堆重放核对每个状态中的摸牌堆，但不会检查其他状态（如手牌、怒气）是否符合游戏规则。单靠本验证器，这种伪造可以通过；但它仍会改变终局审计哈希。任何保存了对局结束时显示的哈希或本机见证侧册的人，都会发现不一致。

联机对局的种子来自开局前已承诺的服务器秘密，并混入每位真人玩家的随机数。承诺公开之后，服务器无法再挑选对自己有利的种子。具体推导见 [SPEC.zh-CN.md](../SPEC.zh-CN.md)。

## 自己动手伪造

[`trial_tamper`](../witness.py) 会在内存副本中改动一次操作的结果，并返回失败的报告。它不重新封好任何哈希，所以验证器还没用到种子，就在审计哈希上判定失败：

```python
from openslay_rng_verifier import load_transcript, trial_tamper

records, _ = load_transcript("examples/training-2v2-seed42.valid.json")
_forged, report = trial_tamper(records, preferred_operation=5)
print(report.status, report.failure_sequence)  # Invalid 93
```

也可以手动编辑真实文件的副本：改动洗牌中的一张牌、某个计数器或某个哈希，然后再次运行验证器。
