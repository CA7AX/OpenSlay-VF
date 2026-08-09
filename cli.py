"""Command-line interface for the standalone verifier."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__
from .localization import LANGUAGE_CHOICES, format_human_report, format_input_error
from .rules import load_ruleset, verify_declared_rules
from .verifier import load_transcript, verify_records
from .witness import load_witness, verify_witness


def main(argv: Sequence[str] | None = None) -> int:
    # Keep bilingual/CJK output deterministic even under the legacy ANSI code
    # pages used by Windows PowerShell and cmd.exe.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="strict")
    parser = argparse.ArgumentParser(
        prog="openslay-rng-verify",
        add_help=False,
        description=(
            "独立验证 OpenSlay 随机性策牒及可选的本机见证侧册。 / "
            "Independently verify an OpenSlay randomness transcript and optional "
            "local witness sidecar."
        ),
    )
    parser._positionals.title = "位置参数 / positional arguments"
    parser._optionals.title = "选项 / options"
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="显示帮助并退出 / show this help message and exit",
    )
    parser.add_argument(
        "transcript",
        help="回放 JSONL 或紧凑策牒 JSON / Replay JSONL or compact transcript JSON",
    )
    parser.add_argument(
        "--witness",
        metavar="PATH",
        help=(
            "用于交叉核对的本机 randomness_witness JSONL 侧册 / "
            "Local randomness_witness JSONL sidecar to cross-check"
        ),
    )
    parser.add_argument(
        "--rules",
        metavar="PATH",
        help=(
            "用于核对随机输入的公开规则描述文件，或使用 'bundled' / "
            "Public rule descriptor, or 'bundled', used to check declared RNG inputs"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出稳定的机器可读 JSON 报告 / Print a stable machine-readable JSON report",
    )
    parser.add_argument(
        "--language",
        "--lang",
        choices=LANGUAGE_CHOICES,
        default="bilingual",
        help=(
            "人类可读输出语言（默认：bilingual）；不影响 --json / "
            "Human-readable output language (default: bilingual); ignored by --json"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="显示版本并退出 / show program's version number and exit",
    )
    args = parser.parse_args(argv)

    try:
        records, resolved = load_transcript(args.transcript)
        verification = verify_records(records)
        witness = None
        if args.witness:
            header, checkpoints = load_witness(args.witness)
            witness = verify_witness(header, checkpoints, records)
        rules = None
        if args.rules:
            rules = verify_declared_rules(verification, load_ruleset(args.rules))
    except (OSError, ValueError) as exc:
        if args.json:
            print(
                json.dumps(
                    {"status": "Invalid", "summary": str(exc), "exit_code": 1},
                    ensure_ascii=True,
                    sort_keys=True,
                )
            )
        else:
            print(format_input_error(str(exc), args.language))
        return 1

    result: dict[str, Any] = {
        "transcript_path": str(resolved),
        "verification": verification.to_dict(),
    }
    if witness:
        result["witness"] = witness.to_dict()
    if rules:
        result["rules"] = rules.to_dict()
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    else:
        print(
            format_human_report(
                verification,
                transcript_path=str(resolved),
                witness=witness,
                rules=rules,
                language=args.language,
            )
        )

    exit_codes = [verification.exit_code]
    if witness:
        exit_codes.append(witness.exit_code)
    if rules:
        exit_codes.append(rules.exit_code)
    if 1 in exit_codes:
        return 1
    if 2 in exit_codes:
        return 2
    return 0


__all__ = ["main"]
