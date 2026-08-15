"""Bilingual human-readable presentation for verifier reports.

The cryptographic verifier intentionally keeps its status values and JSON
report schema in English so existing integrations remain stable.  This module
is the presentation boundary: command-line tools and other human-facing
callers can render the same report in Chinese, English, or both.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from .rules import RuleVerificationReport
    from .verifier import VerificationReport
    from .witness import WitnessReport


HumanLanguage = Literal["bilingual", "zh", "en"]
LANGUAGE_CHOICES: tuple[HumanLanguage, ...] = ("bilingual", "zh", "en")

_STATUS_ZH = {
    "Verified fair": "验策相合",
    "Verified deterministic": "定策可验",
    "Verified": "已验证",
    "Complete": "完整",
    "Partial": "部分验证",
    "Not checked": "未检查",
    "Missing": "缺失",
    "Unverified": "未验证",
    "Incomplete": "不完整",
    "Invalid": "无效",
}

_VERIFICATION_SUMMARIES_ZH = {
    "Legacy seed-only log: no randomness manifest is present.": (
        "旧版日志仅记录种子，未包含随机性清单，无法进行完整验证。"
    ),
    "The server or training derivation has not been revealed yet.": (
        "服务器或训练模式尚未公开随机性推导材料。"
    ),
    "Transcript used the deprecated unverified RNG adapter.": (
        "策牒使用了已弃用且不可验证的随机数适配器。"
    ),
    "The match aborted before an authoritative deck epoch was recorded.": (
        "对局在权威牌堆纪元写入前已经中止。"
    ),
}

_WITNESS_SUMMARIES_ZH = {
    "This replay was not witnessed by this local client.": (
        "本机客户端没有为这份回放保存见证侧册。"
    ),
    "The terminal transcript is incomplete; retained checkpoints cannot all be matched.": (
        "终局策牒不完整，无法逐一核对本机保存的检查点。"
    ),
    "The transcript can be inspected but cannot claim a complete local witness.": (
        "可以检查这份策牒，但不能据此宣称本机见证完整。"
    ),
    "The local sidecar contains more checkpoints than the transcript.": (
        "本机见证侧册中的检查点多于终局策牒。"
    ),
}

_RULE_SUMMARIES_ZH = {
    "No public ruleset descriptor was supplied.": "未提供公开规则描述文件。",
    "Rule inputs cannot be trusted because transcript verification failed.": (
        "策牒验证失败，因此不能信任其中声明的规则输入。"
    ),
    "Public rules descriptor hash differs from the committed transcript hash.": (
        "公开规则描述文件的哈希与策牒中承诺的哈希不一致。"
    ),
    "Descriptor is not declared compatible with this transcript ruleset.": (
        "公开规则描述文件未声明与这份策牒的规则集兼容。"
    ),
}


def normalize_language(language: str) -> HumanLanguage:
    """Validate and normalize a human-output language name."""

    if language not in LANGUAGE_CHOICES:
        choices = ", ".join(LANGUAGE_CHOICES)
        raise ValueError(f"language must be one of: {choices}")
    return cast(HumanLanguage, language)


def bilingual_label(chinese: str, english: str, language: HumanLanguage) -> str:
    """Return a short label in the requested language."""

    if language == "zh":
        return chinese
    if language == "en":
        return english
    return f"{chinese} / {english}"


def localized_status(status: str, language: HumanLanguage = "bilingual") -> str:
    """Render a stable report status without changing its stored value."""

    language = normalize_language(language)
    chinese = _STATUS_ZH.get(status, status)
    if language == "zh":
        return chinese
    if language == "en":
        return status
    return f"{chinese} / {status}"


def format_input_error(message: str, language: HumanLanguage = "bilingual") -> str:
    """Render a CLI input/loading error while retaining the exact diagnosis."""

    language = normalize_language(language)
    if language == "en":
        return f"Invalid: {message}"
    if language == "zh":
        return f"输入无效（技术原因原文）：{message}"
    return f"输入无效 / Invalid input: {message}"


def format_human_report(
    verification: VerificationReport,
    *,
    transcript_path: str | None = None,
    witness: WitnessReport | None = None,
    rules: RuleVerificationReport | None = None,
    language: HumanLanguage = "bilingual",
) -> str:
    """Format verifier reports for people in Chinese, English, or both.

    Full hashes, counters, purposes, and the original English technical summary
    are retained.  Only presentation changes; callers that require a stable
    machine contract should continue to use each report's ``to_dict()`` method.
    """

    language = normalize_language(language)
    lines = [
        bilingual_label(
            "OpenSlay 随机性验证报告",
            "OpenSlay Randomness Verification Report",
            language,
        )
    ]
    if transcript_path:
        lines.append(
            f"{bilingual_label('策牒路径', 'Transcript', language)}: {transcript_path}"
        )
    lines.extend(_format_verification(verification, language))
    if witness is not None:
        lines.append("")
        lines.extend(_format_witness(witness, language))
    if rules is not None:
        lines.append("")
        lines.extend(_format_rules(rules, language))
    return "\n".join(lines)


def _format_verification(
    report: VerificationReport,
    language: HumanLanguage,
) -> list[str]:
    lines = [
        (
            f"{bilingual_label('验证状态', 'Verification status', language)}: "
            f"{localized_status(report.status, language)}"
        )
    ]
    _append_summary(
        lines,
        _verification_summary_zh(report, include_english_fallback=language == "zh"),
        report.summary,
        language,
    )
    lines.append(
        f"{bilingual_label('随机操作数', 'Random operations', language)}: "
        f"{report.operation_count}"
    )
    lines.append(
        f"{bilingual_label('已验证牌堆纪元', 'Deck epochs verified', language)}: "
        f"{report.deck_epochs_verified}"
    )
    if report.failure_sequence is not None:
        lines.append(
            f"{bilingual_label('失败记录序号', 'Failure record sequence', language)}: "
            f"{report.failure_sequence}"
        )
    if report.failure_operation_sequence is not None:
        lines.append(
            f"{bilingual_label('失败随机操作', 'Failure operation', language)}: "
            f"{report.failure_operation_sequence}"
        )
    if report.failure_purpose:
        lines.append(
            f"{bilingual_label('失败用途', 'Failure purpose', language)}: "
            f"{report.failure_purpose}"
        )
    if report.final_audit_hash:
        lines.append(
            f"{bilingual_label('终局审计哈希', 'Final audit hash', language)}: "
            f"{report.final_audit_hash}"
        )
    return lines


def _format_witness(report: WitnessReport, language: HumanLanguage) -> list[str]:
    lines = [
        (
            f"{bilingual_label('本机见证', 'Local witness', language)}: "
            f"{localized_status(report.status, language)}"
        )
    ]
    _append_summary(
        lines,
        _witness_summary_zh(report, include_english_fallback=language == "zh"),
        report.summary,
        language,
    )
    lines.append(
        f"{bilingual_label('检查点', 'Checkpoints', language)}: "
        f"{report.checkpoint_count}/{report.operation_count}"
    )
    if report.failure_operation_sequence is not None:
        lines.append(
            f"{bilingual_label('失败随机操作', 'Failure operation', language)}: "
            f"{report.failure_operation_sequence}"
        )
    if report.short_fingerprint != "—":
        lines.append(
            f"{bilingual_label('终局短印', 'Final seal', language)}: "
            f"{report.short_fingerprint}"
        )
    return lines


def _format_rules(
    report: RuleVerificationReport,
    language: HumanLanguage,
) -> list[str]:
    lines = [
        (
            f"{bilingual_label('公开规则', 'Public rules', language)}: "
            f"{localized_status(report.status, language)}"
        )
    ]
    _append_summary(
        lines,
        _rules_summary_zh(report, include_english_fallback=language == "zh"),
        report.summary,
        language,
    )
    lines.append(
        f"{bilingual_label('已核对随机操作', 'Operations checked', language)}: "
        f"{report.checked_operation_count}"
    )
    if report.unlisted_purposes:
        lines.append(
            f"{bilingual_label('尚未描述的用途', 'Unlisted purposes', language)}: "
            f"{', '.join(report.unlisted_purposes)}"
        )
    if report.failure_operation_sequence is not None:
        lines.append(
            f"{bilingual_label('失败随机操作', 'Failure operation', language)}: "
            f"{report.failure_operation_sequence}"
        )
    if report.failure_purpose:
        lines.append(
            f"{bilingual_label('失败用途', 'Failure purpose', language)}: "
            f"{report.failure_purpose}"
        )
    if report.descriptor_hash:
        lines.append(
            f"{bilingual_label('公开规则哈希', 'Public rules hash', language)}: "
            f"{report.descriptor_hash}"
        )
    return lines


def _append_summary(
    lines: list[str],
    chinese: str,
    english: str,
    language: HumanLanguage,
) -> None:
    label = bilingual_label("摘要", "Summary", language)
    if language == "zh":
        lines.append(f"{label}: {chinese}")
    elif language == "en":
        lines.append(f"{label}: {english}")
    else:
        lines.extend((f"{label}:", f"  中文：{chinese}", f"  English: {english}"))


def _verification_summary_zh(
    report: VerificationReport,
    *,
    include_english_fallback: bool,
) -> str:
    if report.status == "Verified fair":
        return (
            f"验策相合：已核验 {report.operation_count} 次随机操作和 "
            f"{report.deck_epochs_verified} 个牌堆纪元。"
        )
    if report.status == "Verified deterministic":
        return (
            f"定策可验：已核验 {report.operation_count} 次随机操作和 "
            f"{report.deck_epochs_verified} 个牌堆纪元。"
        )
    translated = _VERIFICATION_SUMMARIES_ZH.get(report.summary)
    if translated:
        return translated
    prefix = {
        "Invalid": "随机性策牒无效。",
        "Incomplete": "随机性策牒不完整。",
        "Unverified": "随机性策牒尚未得到验证。",
    }.get(report.status, "随机性验证已完成。")
    return _with_technical_fallback(prefix, report.summary, include_english_fallback)


def _witness_summary_zh(
    report: WitnessReport,
    *,
    include_english_fallback: bool,
) -> str:
    if report.status == "Complete":
        return (
            "所提供的策牒检查点与终局记录逐条相等；"
            "此结果本身不证明这些检查点是在对局过程中保存的。"
        )
    translated = _WITNESS_SUMMARIES_ZH.get(report.summary)
    if translated:
        return translated
    if report.status == "Incomplete" and report.failure_operation_sequence is not None:
        return f"本机见证不完整：缺少第 {report.failure_operation_sequence} 笔及之后的检查点。"
    prefix = {
        "Invalid": "本机见证无效。",
        "Incomplete": "本机见证不完整。",
        "Missing": "本机见证缺失。",
    }.get(report.status, "本机见证检查已完成。")
    return _with_technical_fallback(prefix, report.summary, include_english_fallback)


def _rules_summary_zh(
    report: RuleVerificationReport,
    *,
    include_english_fallback: bool,
) -> str:
    if report.status == "Verified":
        return f"全部 {report.checked_operation_count} 次随机操作均符合公开规则描述。"
    if report.status == "Partial":
        return (
            f"已有 {report.checked_operation_count} 次随机操作符合公开规则；"
            f"仍有 {len(report.unlisted_purposes)} 种用途尚未描述。"
        )
    translated = _RULE_SUMMARIES_ZH.get(report.summary)
    if translated:
        return translated
    prefix = {
        "Invalid": "公开规则核验失败。",
        "Not checked": "未核验公开规则。",
    }.get(report.status, "公开规则核验已完成。")
    return _with_technical_fallback(prefix, report.summary, include_english_fallback)


def _with_technical_fallback(
    prefix: str,
    english_summary: str,
    include_english_fallback: bool,
) -> str:
    if not include_english_fallback:
        return prefix
    return f"{prefix} 技术原因（英文原文）：{english_summary}"


__all__ = [
    "HumanLanguage",
    "LANGUAGE_CHOICES",
    "bilingual_label",
    "format_human_report",
    "format_input_error",
    "localized_status",
    "normalize_language",
]
