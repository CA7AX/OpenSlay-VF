<p align="center">
  <img src="https://raw.githubusercontent.com/CA7AX/OpenSlay-VF/main/assets/openslay-water-ink-poster.png" alt="OpenSlay 水墨横幅：Without verification comes no fairness." width="100%">
</p>

<h1 align="center">⚔️ OpenSlay 随机性验证器 ⚔️</h1>

<p align="center"><em>Without verification comes no fairness. 不经验证，无以言公。</em></p>

<p align="center">
  <strong>不要相信，去重算。</strong><br/>
  <sub>独立于私有游戏引擎、仅依赖 Python 标准库的 OpenSlay 随机性策牒生成与验证工具。</sub>
</p>

<p align="center">
  <a href="https://github.com/CA7AX/OpenSlay-VF/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/CA7AX/OpenSlay-VF/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-355f52?logo=python&logoColor=white">
  <img alt="运行时依赖：0" src="https://img.shields.io/badge/runtime%20dependencies-0-355f52">
  <a href="LICENSE"><img alt="BSD-3-Clause" src="https://img.shields.io/badge/license-BSD--3--Clause-8d3b2f"></a>
  <a href="SPEC.zh-CN.md"><img alt="协议 v2" src="https://img.shields.io/badge/%E5%8D%8F%E8%AE%AE-v2-9B3A32"></a>
</p>

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-%E5%B7%B2%E6%94%AF%E6%8C%81-1f6feb?logo=linux&logoColor=white">
  <img alt="macOS" src="https://img.shields.io/badge/macOS-%E5%B7%B2%E6%94%AF%E6%8C%81-1f6feb?logo=apple&logoColor=white">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-%E5%B7%B2%E6%94%AF%E6%8C%81-1f6feb?logo=windows&logoColor=white">
  <img alt="中英双语报告" src="https://img.shields.io/badge/%E6%8A%A5%E5%91%8A-%E4%B8%AD%20%2F%20EN%20%E5%8F%8C%E8%AF%AD-8d3b2f">
  <img alt="不导入私有引擎" src="https://img.shields.io/badge/%E7%A7%81%E6%9C%89%E5%BC%95%E6%93%8E%E5%AF%BC%E5%85%A5-%E9%9B%B6-black">
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <strong>简体中文</strong> ·
  <a href="SPEC.zh-CN.md">协议规范</a> ·
  <a href="CONTRIBUTING.md">参与贡献</a> ·
  <a href="SECURITY.md">安全策略</a>
</p>

<p align="center">
  <a href="#overview">概览</a> ·
  <a href="#scope">验证边界</a> ·
  <a href="#quick-start">快速开始</a> ·
  <a href="#flow">验证流程</a> ·
  <a href="#results">结果语义</a> ·
  <a href="#python-api">Python API</a> ·
  <a href="#code-map">代码地图</a>
</p>

---

<a id="overview"></a>

## 🧭 从“相信”走向“可复核”

OpenSlay-VF 读取终局随机性策牒，**把每一次随机操作从头独立重放**——承诺、种子派生、HMAC 数据流、哈希链、终局揭示——全程不需要 OpenSlay 私有源码，也不增加运行时依赖。对于在线对局，重算所需的真人客户端 nonce 和单局服务器秘密由终局策牒公开提供；验证器无需额外的 nonce 输入，也不接触仍属私密的部署凭据。公开材料重算不出来，策牒就过不了。就这么简单。

下面是简化示例：摘要与细节行已省略，哈希也仅作缩写展示。

```console
$ openslay-rng-verify /path/to/match.jsonl --rules bundled

OpenSlay 随机性验证报告 / OpenSlay Randomness Verification Report
[… 已省略策牒路径 …]
验证状态 / Verification status: 验策相合 / Verified fair
[… 已省略验证摘要 …]
随机操作数 / Random operations: 312
已验证牌堆纪元 / Deck epochs verified: 2
终局审计哈希 / Final audit hash: 9f2c…e41a

公开规则 / Public rules: 已验证 / Verified
[… 已省略规则摘要、数量与描述文件哈希 …]

$ echo $?
0
```

<table align="center">
<tr>
<th>🔁 可复现</th>
<th>🔗 可追踪</th>
<th>🧱 相互独立</th>
<th>🪶 轻量运行</th>
</tr>
<tr>
<td>从公开终局材料重放随机操作</td>
<td>每一步绑定状态、上下文与顺序</td>
<td>运行时从不导入私有游戏引擎</td>
<td>Python 3.10+，零第三方运行时依赖</td>
</tr>
</table>

协议编码、有界 HMAC 数据流、语义随机操作、通用随机预言机、策牒验证、本机见证核对、命令行界面与公开数据均由本仓库维护。完整协议见 [SPEC.zh-CN.md](SPEC.zh-CN.md)。应用创建通用随机预言机时，必须明确提供规则集哈希。

> [!WARNING]
> 所有 `0.x` 版本均为开发预发布，协议、报告格式与公开规则覆盖面仍可能演进。随包提供的原型规则描述文件明确为**部分（Partial）**；稳定的 `1.0` 版本要求完整规则描述文件，并将其哈希绑定进游戏策牒。

<a id="scope"></a>

## ⚖️ 它验证什么，又不证明什么

<table>
<tr>
<th>✅ 能验证</th>
<th>🚫 不证明</th>
</tr>
<tr>
<td>

- 开局前服务器承诺与玩家贡献的结构、顺序和终局公开材料是否相合
- 每次状态绑定的 HMAC-SHA256 随机操作、证明和结果能否独立重算
- 规范化的操作前状态/上下文摘要、用途计数器、全局操作顺序及策牒哈希链
- 终局公开材料、操作总数与最终审计哈希是否一致
- 可选 `randomness_witness` 是否与所提供的逐步检查点一致
- 可选公开数据规则描述文件中已列出的随机输入是否匹配

</td>
<td>

- 服务器秘密或玩家 nonce 的熵质量，以及参与方本身是否诚实
- 私有事件引擎是否正确执行了全部非随机游戏规则
- 规则设计是否平衡、比赛是否完整结束，或游戏整体公平性
- 所有客户端在实时过程中是否收到同一份历史
- 单个本机见证之外其他玩家实际看到的内容
- **部分**描述文件尚未列出的用途是否符合规则

</td>
</tr>
</table>

`Complete` 本机见证只证明终局策牒与所提供的检查点相等。若要把这些检查点解释为对局过程中保存的本机记录，还需要可信且不可改写的本机来源；即便如此，也不能证明其他客户端看到了什么。玩家可以比较完整的 256 位终局审计哈希，在哈希层面比较受哈希覆盖的随机性记录上下文；该哈希不覆盖外层元数据，也不能标识任意非随机游戏历史或界面历史。五组短印只是便于人工核对的 80 位前缀：它能快速发现许多不一致，但短印相同不等于完整哈希相同。

本仓库不包含游戏引擎、角色实现、服务器、匹配系统、界面或私有构建源码，也不会导入 `openslay`、`openslay_server` 或 `game_mode`。

<a id="quick-start"></a>

## 🚀 快速开始

```bash
git clone https://github.com/CA7AX/OpenSlay-VF.git
cd OpenSlay-VF
python -m pip install -e .
openslay-rng-verify --version
openslay-rng-verify /path/to/match.jsonl
```

常用组合：

```bash
# 稳定的机器可读 JSON
openslay-rng-verify /path/to/transcript.json --json

# 同时交叉核对本机见证侧册
openslay-rng-verify /path/to/match.jsonl \
  --witness /path/to/randomness_witness/<match-hash>.jsonl

# 同时核对随包公开规则（当前为部分描述）
openslay-rng-verify /path/to/match.jsonl --rules bundled

# 选择人类可读报告语言
openslay-rng-verify /path/to/match.jsonl --language zh
openslay-rng-verify /path/to/match.jsonl --language en
```

也可以使用 `python -m openslay_rng_verifier`，参数完全相同。人类可读报告默认中英双语；`--json` 不受语言选项影响，机器可读字段名与状态值保持稳定。

策牒参数支持完整游戏 JSONL 回放、包含 `records` 的紧凑 JSON 对象，或策牒记录 JSON 列表。目录输入的范围更窄：验证器会递归搜索游戏 `*.jsonl` 日志，并选择最新的可识别文件；目录中的紧凑 `.json` 策牒不会被发现。只有 JSONL 末行未完成写入时，才可能被区分为末尾截断与策牒不完整；损坏或截断的紧凑 JSON 属于无效输入。

<a id="flow"></a>

## 🔬 五步验证流程

```mermaid
flowchart LR
    A["1 · 严格读取<br/>拒绝非法结构"] --> B["2 · 核对开局材料<br/>承诺先于贡献"]
    B --> C["3 · 重建主种子<br/>独立重新派生"]
    C --> D["4 · 逐项重放<br/>重算每个随机操作"]
    D --> E["5 · 封存结论<br/>审计哈希 + 见证 + 规则"]
```

1. **严格读取**：解析 JSONL 或紧凑 JSON，拒绝重复键、非有限数字、非法 UTF-8 与不规范结构；对未完成写入的 JSONL 末行，还会区分可识别的末尾截断与损坏。
2. **核对开局材料**：验证模式、协议版本、规则集哈希与收据结构；在线模式检查策牒所声明的承诺与贡献顺序是否自洽，训练模式检查公开种子的规范表达。该顺序来自策牒自身，不是外部时间戳，也不证明服务器诚实。
3. **重建主种子**：在线模式用终局公开的服务器秘密与有效玩家贡献重新派生；训练模式用声明的数值种子与公开随机性输入重新派生。
4. **逐项重放**：重算每个 `probability`、`choice`、`sample` 或 `shuffle` 操作，并核对结果、证明、状态/上下文摘要、用途计数器、全局顺序、牌堆 epoch 与连续审计哈希。
5. **封存结论**：核对终局公开材料、操作总数和最终审计哈希，再按需交叉核对本机见证与公开规则描述文件，生成稳定状态和退出码。

```text
策牒输入 → 开局承诺/种子 → 逐项重放 → 审计哈希链 → 终局 + 见证 + 规则报告
```

<a id="results"></a>

## 📜 结果与退出码

主验证状态保持英文不变，便于脚本稳定消费：

| 状态 | 含义 | 退出码 |
| --- | --- | :---: |
| `Verified fair` | 在线随机性收据在协议假设内通过；不是对整场游戏公平性的认证 | `0` |
| `Verified deterministic` | 训练对局可由声明的种子和公开输入精确复现 | `0` |
| `Invalid` | 数据无效、冲突、被篡改，或无法满足协议约束 | `1` |
| `Incomplete` | 公开材料、终局揭示或所请求的检查点尚不完整 | `2` |
| `Unverified` | 旧式仅种子日志、已弃用/未验证随机源，或缺少可验证清单 | `2` |

可选层使用各自的稳定状态：本机见证为 `Complete`、`Missing`、`Incomplete`、`Invalid`；公开规则为 `Verified`、`Partial`、`Not checked`、`Invalid`。`Partial` 表示已描述的随机操作均匹配，但描述文件有意允许尚未列出的用途。

命令行会合并所有已请求检查的退出码：任一检查为 `1`，整体返回 `1`；否则任一检查为 `2`，整体返回 `2`；只有所有已请求检查都完整通过时才返回 `0`。

在进入验证之前，`argparse` 也会对命令行用法错误返回退出码 `2`，例如缺少策牒参数、使用未知选项或提供无效的选项值。这类错误会写入标准错误，不表示验证结果为 `Incomplete` 或 `Unverified`。

<a id="python-api"></a>

## 🐍 Python API

```python
from openslay_rng_verifier import (
    format_human_report,
    load_transcript,
    verify_records,
)

records, resolved_path = load_transcript("match.jsonl")
report = verify_records(records)

print(report.status, report.final_audit_hash)
print(format_human_report(report, language="bilingual"))
```

本机见证与公开规则是独立的可选检查：

```python
from openslay_rng_verifier import (
    load_ruleset,
    load_witness,
    verify_declared_rules,
    verify_witness,
)

header, checkpoints = load_witness("witness.jsonl")
witness = verify_witness(header, checkpoints, records)

rules = verify_declared_rules(report, load_ruleset("bundled"))
print(witness.status, witness.short_fingerprint)
print(rules.status, rules.descriptor_hash)
```

<a id="code-map"></a>

## 🗺️ 代码库地图

| 路径 | 职责 |
| --- | --- |
| `protocol.py` | 规范 JSON、域分隔摘要、承诺与种子派生、协议约束 |
| `oracle.py` · `operations.py` | 通用随机预言机、有界 HMAC 数据流与四类语义随机操作 |
| `verifier.py` | 策牒加载、结构检查、逐项重放与主验证报告 |
| `witness.py` | 追加式本机见证侧册加载、检查点核对与短印 |
| `rules.py` · `data/` | 数据化公开规则核对、原型牌堆与**部分**规则描述文件 |
| `cli.py` · `localization.py` | 命令行入口、稳定 JSON 和中英双语人类报告 |
| `test-vectors/` · `tests/` | 固定协议向量、篡改测试、边界与独立性回归测试 |
| `tools/` · `.github/workflows/` | 公共文件边界、构建/产物审计、CI 与发布门禁 |

<a id="development"></a>

## 🛡️ 开发、发布与安全

```bash
python -m pip install -e ".[test]"
python tools/release_gate.py --mode ci
python -m pytest -q
```

贡献须同时维护公开协议、验证器与不可变测试向量；凡改变规范字节、摘要输入、可接受策牒结构、随机操作语义或域分隔标签的修改，都必须升级协议或算法版本。详细约定见 [CONTRIBUTING.md](CONTRIBUTING.md)，发布流程见 [RELEASING.md](RELEASING.md)。

请勿在公开 issue 中披露验证器漏洞，也不要提交真实对局策牒、本机见证、客户端 nonce、凭据、私有 OpenSlay 源码、本机路径或专有资源。请按 [SECURITY.md](SECURITY.md) 使用 GitHub 私密漏洞报告。`test-vectors/` 中的 `server_secret`、nonce 与规则集哈希都是公开的合成测试材料，不是部署凭据。

本项目采用 [BSD-3-Clause](LICENSE) 许可证。

---

<p align="center">
  <sub>⚔️ <strong>Without verification comes no fairness. 不经验证，无以言公。</strong> ⚔️</sub>
</p>
