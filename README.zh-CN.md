# openslay-rng-verifier

[English](README.md) | 简体中文

这是一个独立、仅依赖 Python 标准库的 OpenSlay 随机性策牒生成与验证工具。

本库不包含游戏引擎、角色实现、服务器、匹配系统、界面或私有构建源码。它只验证公开协议中的下列内容：

1. 开局前的服务器承诺与玩家贡献；
2. 每一次与游戏状态绑定的 HMAC-SHA256 随机操作及其证明；
3. 操作前规范状态与上下文摘要、各用途计数器、全局操作顺序以及策牒哈希链；
4. 终局公开材料与最终审计哈希；
5. 可选的本机 `randomness_witness` 见证侧册；
6. 可选的公开数据规则描述文件，用于核对随机操作的输入。

协议细节见 [SPEC.zh-CN.md](SPEC.zh-CN.md)。

此包自行实现协议编码、有界 HMAC 数据流、随机操作语义、通用随机预言机、策牒验证、本机见证核对、命令行界面及公开数据。它从不导入 OpenSlay 游戏引擎。应用在创建通用随机预言机时必须明确提供规则集哈希。

## 从本仓库安装并运行

本仓库根目录同时也是 Python 包目录。调用模块或命令行入口前，请先以
editable 模式安装：

```bash
python -m pip install -e .
openslay-rng-verify --version
```

```bash
python -m openslay_rng_verifier /path/to/match.jsonl
python -m openslay_rng_verifier /path/to/transcript.json --json
python -m openslay_rng_verifier /path/to/match.jsonl \
  --witness /path/to/randomness_witness/<match-hash>.jsonl
python -m openslay_rng_verifier /path/to/match.jsonl --rules bundled
python -m openslay_rng_verifier /path/to/match.jsonl --language zh
python -m openslay_rng_verifier /path/to/match.jsonl --language en
```

`openslay-rng-verify` 命令行入口接受相同参数。

人类可读的命令行报告默认同时显示中文和英文。可以使用 `--language bilingual`、`--language zh` 或 `--language en` 选择显示语言。`--json` 不受语言选项影响，机器可读字段名和状态值保持稳定。

退出码：完整完成所请求的验证时为 `0`；数据无效或相互冲突时为 `1`；数据不完整、未验证、仅部分验证或缺失时为 `2`。

策牒参数可以是：

- 完整游戏 JSONL 回放；
- 包含 `records` 的紧凑 JSON 对象；
- 策牒记录组成的 JSON 列表；
- 一个目录，此时会选择其中最新的可识别策牒。

## Python API

```python
from openslay_rng_verifier import load_transcript, verify_records

records, resolved_path = load_transcript("match.jsonl")
report = verify_records(records)
print(report.status, report.final_audit_hash)
```

需要面向用户显示双语报告时，可以在不改变原始报告对象的情况下使用：

```python
from openslay_rng_verifier import format_human_report

print(format_human_report(report, language="bilingual"))
```

核对本机见证侧册：

```python
from openslay_rng_verifier import load_witness, verify_witness

header, checkpoints = load_witness("witness.jsonl")
witness = verify_witness(header, checkpoints, records)
print(witness.status, witness.short_fingerprint)
```

## 验证结果的含义

- `验策相合 / Verified fair`：在线模式的服务器承诺、玩家贡献、终局公开材料和全部随机操作均通过验证。
- `定策可验 / Verified deterministic`：训练模式对局可以根据其声明的种子和公开输入精确复现。
- `完整 / Complete` 本机见证：终局策牒与本机在游戏过程中保存的每一个检查点一致。
- `部分验证 / Partial` 公开规则：已描述的随机操作均匹配，但所提供的公开描述文件有意允许尚未描述的用途。

本机见证只能证明终局策牒与该客户端在游戏中所见的内容一致，不能证明所有客户端都收到了同一份实时历史。玩家可以比较完整终局审计哈希或五组短印，以发现彼此不同的终局历史。

## 不公开引擎源码的规则核对

玩家可以人工比较策牒中的 `purpose` 和 `inputs` 与公开卡牌或技能说明。程序也可以使用公开描述文件里的 `operation_rules` 自动核对，例如：

```json
{
  "operation": "probability",
  "purpose": "environment.thunder.self-damage",
  "input_constraints": {
    "numerator": {"equals": 1},
    "denominator": {"equals": 4}
  },
  "rule_reference": "环境牌 · 引雷"
}
```

这里公开的是规则和概率，而不是实现这些规则的事件引擎。在每个随机用途都有稳定的公开说明之前，随包提供的原型规则描述文件明确标记为“部分”。

## 独立发布

本目录本身就是一个完整的 Python 项目，包含包元数据、MIT 许可证、协议规范、测试、公开数据和命令行入口。可以在不包含 OpenSlay 游戏包的环境中单独构建并安装 wheel。`test-vectors/` 中的 `server_secret`、nonce 与规则集哈希均为公开的合成测试材料，并非实际部署凭据。

所有 `0.x` 版本均为开发预发布。发布稳定的 `1.0` 版本前，应发布完整的规则描述文件，并将其哈希绑定到游戏策牒中。
