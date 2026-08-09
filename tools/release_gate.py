#!/usr/bin/env python3
"""Validate the public verifier source tree and release tag."""

from __future__ import annotations

import argparse
import ast
import binascii
import hashlib
import json
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "PUBLIC_FILES.txt"
VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?"
    r"(?:\.dev[0-9]+)?$"
)
LOCAL_PATH_MARKERS = (
    b"/" + b"Users/",
    b"/" + b"home/",
    b"C:" + b"\\" + b"Users\\",
    b"C:" + b"/" + b"Users/",
)
FORBIDDEN_TRACKED_PARTS = {
    ".env",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "logs",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".key",
    ".log",
    ".pem",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_README_PNG_BYTES = 12 * 1024 * 1024
MAX_README_PNG_PIXELS = 12_000_000
README_PNG_RULES = {
    "assets/openslay-water-ink-logo.png": {
        "min_width": 256,
        "max_width": 2048,
        "min_height": 256,
        "max_height": 2048,
        "min_aspect": 0.5,
        "max_aspect": 2.0,
        "color_types": {6},  # RGBA: the standalone mark must retain transparency.
    },
    "assets/openslay-water-ink-poster.png": {
        "min_width": 960,
        "max_width": 4096,
        "min_height": 320,
        "max_height": 2048,
        "min_aspect": 2.0,
        "max_aspect": 4.0,
        "color_types": {2, 6},  # RGB or RGBA.
    },
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release gate failed: {message}")


def git(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        fail(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def package_version() -> str:
    tree = ast.parse((ROOT / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            version = node.value.value
            if VERSION_RE.fullmatch(version) is None:
                fail(f"unsupported package version: {version!r}")
            return version
    fail("__init__.py does not contain one literal __version__ assignment")


def declared_files() -> list[str]:
    if not MANIFEST_PATH.is_file():
        fail("PUBLIC_FILES.txt is missing")
    records = [
        line.strip()
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if records != sorted(set(records), key=lambda value: value.encode("utf-8")):
        fail("PUBLIC_FILES.txt must be unique and bytewise sorted")
    return records


def tracked_files() -> list[str]:
    records = [record for record in git("ls-files", "-z").split("\0") if record]
    return sorted(records, key=lambda value: value.encode("utf-8"))


def verify_manifest() -> list[str]:
    declared = declared_files()
    tracked = tracked_files()
    if declared != tracked:
        missing = sorted(set(declared) - set(tracked))
        unexpected = sorted(set(tracked) - set(declared))
        details: list[str] = []
        if missing:
            details.append("declared but untracked: " + ", ".join(missing))
        if unexpected:
            details.append("tracked but undeclared: " + ", ".join(unexpected))
        fail("public file manifest mismatch (" + "; ".join(details) + ")")

    for record in git("ls-files", "--stage", "-z").split("\0"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        mode = metadata.split(" ", 1)[0]
        if mode not in {"100644", "100755"}:
            fail(f"tracked symlink, submodule, or special file is forbidden: {path} ({mode})")
    return tracked


def _png_error(rendered: str, detail: str) -> NoReturn:
    fail(f"invalid README PNG {rendered}: {detail}")


def verify_readme_png(rendered: str, data: bytes) -> None:
    """Validate the two narrowly permitted binary README assets using stdlib only."""

    rules = README_PNG_RULES.get(rendered)
    if rules is None:
        fail(f"binary file is outside the public contract: {rendered}")
    if len(data) > MAX_README_PNG_BYTES:
        _png_error(rendered, f"file exceeds {MAX_README_PNG_BYTES} bytes")
    if not data.startswith(PNG_SIGNATURE):
        _png_error(rendered, "signature is missing or corrupt")

    offset = len(PNG_SIGNATURE)
    chunk_index = 0
    ihdr: tuple[int, int, int, int, int, int, int] | None = None
    idat_parts: list[bytes] = []
    idat_closed = False
    saw_iend = False
    while offset < len(data):
        if len(data) - offset < 12:
            _png_error(rendered, "truncated chunk header")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(data):
            _png_error(rendered, "truncated chunk payload")
        chunk_data = data[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack(">I", data[offset + 8 + length : chunk_end])[0]
        actual_crc = binascii.crc32(chunk_type)
        actual_crc = binascii.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            name = chunk_type.decode("ascii", errors="replace")
            _png_error(rendered, f"CRC mismatch in {name} chunk")
        if len(chunk_type) != 4 or not all(
            ord("A") <= value <= ord("Z") or ord("a") <= value <= ord("z")
            for value in chunk_type
        ):
            _png_error(rendered, "invalid chunk type")

        if chunk_index == 0 and chunk_type != b"IHDR":
            _png_error(rendered, "IHDR is not the first chunk")
        if chunk_type == b"IHDR":
            if ihdr is not None or length != 13:
                _png_error(rendered, "IHDR is duplicated or malformed")
            ihdr = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            if ihdr is None or idat_closed:
                _png_error(rendered, "IDAT chunks are out of order")
            idat_parts.append(chunk_data)
        elif chunk_type == b"IEND":
            if length != 0 or not idat_parts:
                _png_error(rendered, "IEND is malformed or precedes image data")
            if chunk_end != len(data):
                _png_error(rendered, "data follows IEND")
            saw_iend = True
        elif chunk_type[0] & 0x20 == 0:
            name = chunk_type.decode("ascii", errors="replace")
            _png_error(rendered, f"unsupported critical chunk {name}")

        if idat_parts and chunk_type not in {b"IDAT", b"IEND"}:
            idat_closed = True
        offset = chunk_end
        chunk_index += 1
        if saw_iend:
            break

    if ihdr is None or not idat_parts or not saw_iend:
        _png_error(rendered, "required IHDR, IDAT, or IEND chunk is missing")

    width, height, bit_depth, color_type, compression, filtering, interlace = ihdr
    if not (rules["min_width"] <= width <= rules["max_width"]):
        _png_error(rendered, f"width {width} is outside the permitted range")
    if not (rules["min_height"] <= height <= rules["max_height"]):
        _png_error(rendered, f"height {height} is outside the permitted range")
    if width * height > MAX_README_PNG_PIXELS:
        _png_error(rendered, f"image exceeds {MAX_README_PNG_PIXELS} pixels")
    aspect = width / height
    if not (rules["min_aspect"] <= aspect <= rules["max_aspect"]):
        _png_error(rendered, f"aspect ratio {aspect:.3f} is outside the permitted range")
    if bit_depth != 8 or color_type not in rules["color_types"]:
        _png_error(rendered, f"unsupported bit depth/color type {bit_depth}/{color_type}")
    if (compression, filtering, interlace) != (0, 0, 0):
        _png_error(
            rendered,
            "only standard compression/filtering and non-interlaced data are allowed",
        )

    channels = {2: 3, 6: 4}[color_type]
    row_size = 1 + width * channels
    expected_size = row_size * height
    decompressor = zlib.decompressobj()
    try:
        pixels = decompressor.decompress(b"".join(idat_parts), expected_size + 1)
    except zlib.error as error:
        _png_error(rendered, f"IDAT stream is not decodable: {error}")
    if (
        len(pixels) != expected_size
        or not decompressor.eof
        or decompressor.unconsumed_tail
        or decompressor.unused_data
    ):
        _png_error(rendered, "decoded scanline length or zlib stream boundary is invalid")
    for row in range(height):
        filter_type = pixels[row * row_size]
        if filter_type > 4:
            _png_error(rendered, f"scanline {row} uses invalid filter {filter_type}")


def verify_paths_and_contents(paths: list[str]) -> None:
    for rendered in paths:
        path = Path(rendered)
        if path.is_absolute() or ".." in path.parts:
            fail(f"unsafe tracked path: {rendered}")
        if FORBIDDEN_TRACKED_PARTS.intersection(path.parts):
            fail(f"private/generated path is tracked: {rendered}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or any(
            part.endswith(".egg-info") for part in path.parts
        ):
            fail(f"private/generated file is tracked: {rendered}")
        data = (ROOT / path).read_bytes()
        if rendered in README_PNG_RULES:
            verify_readme_png(rendered, data)
        elif b"\0" in data:
            fail(f"binary file is outside the public contract: {rendered}")
        for marker in LOCAL_PATH_MARKERS:
            if marker in data:
                fail(f"local absolute path marker {marker!r} occurs in {rendered}")


def verify_metadata(version: str) -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if 'dynamic = ["version"]' not in pyproject:
        fail("pyproject.toml must source the version dynamically")
    if 'version = {attr = "openslay_rng_verifier.__version__"}' not in pyproject:
        fail("pyproject.toml does not source version from __version__")
    if f"## {version} -" not in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"):
        fail(f"CHANGELOG.md has no dated {version} section")


def descriptor_is_partial() -> bool:
    descriptor_path = ROOT / "data" / "openslay-prototype-v1.partial.json"
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    filename_partial = descriptor_path.name.endswith(".partial.json")
    identifier_partial = str(descriptor.get("ruleset_id", "")).endswith("-partial")
    allow_partial = descriptor.get("allow_unlisted_purposes") is True
    if len({filename_partial, identifier_partial, allow_partial}) != 1:
        fail("rules descriptor partial markers disagree")
    for readme in (ROOT / "README.md", ROOT / "README.zh-CN.md"):
        if "partial" not in readme.read_text(encoding="utf-8").lower() and "部分" not in readme.read_text(
            encoding="utf-8"
        ):
            fail(f"{readme.name} does not disclose the partial rules descriptor")
    return allow_partial


def source_fingerprint(paths: list[str]) -> str:
    records: list[str] = []
    for rendered in paths:
        data = (ROOT / rendered).read_bytes()
        digest = hashlib.sha256(data).hexdigest().upper()
        records.append(f"{rendered}\t{len(data)}\t{digest}")
    payload = ("openslay-public-verifier-tree-v1\n" + "\n".join(records)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().upper()


def verify_release_tag(tag: str, version: str) -> None:
    expected = f"v{version}"
    if tag != expected:
        fail(f"tag {tag!r} does not exactly match {expected!r}")
    if git("cat-file", "-t", tag).strip() != "tag":
        fail("release tags must be annotated (and signed when practical)")
    if git("rev-list", "-n", "1", tag).strip() != git("rev-parse", "HEAD").strip():
        fail("release tag does not resolve to the checked-out commit")
    if git("status", "--porcelain").strip():
        fail("release checkout is not clean")


def write_github_output(path: Path, *, version: str, prerelease: bool, fingerprint: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"version={version}\n")
        stream.write(f"prerelease={'true' if prerelease else 'false'}\n")
        stream.write(f"source_sha256={fingerprint}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("ci", "release"), default="ci")
    parser.add_argument("--tag")
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    version = package_version()
    match = VERSION_RE.fullmatch(version)
    assert match is not None
    paths = verify_manifest()
    verify_paths_and_contents(paths)
    verify_metadata(version)
    partial = descriptor_is_partial()
    major = int(match.group("major"))
    prerelease = major == 0 or partial or any(marker in version for marker in ("a", "b", "rc", "dev"))
    if arguments.mode == "release":
        if not arguments.tag:
            fail("--tag is required in release mode")
        if partial and major >= 1:
            fail("v1+ releases require a complete bundled rules descriptor")
        verify_release_tag(arguments.tag, version)
    elif arguments.tag:
        fail("--tag is valid only in release mode")

    fingerprint = source_fingerprint(paths)
    if arguments.github_output is not None:
        write_github_output(
            arguments.github_output,
            version=version,
            prerelease=prerelease,
            fingerprint=fingerprint,
        )
    print(f"version={version}")
    print(f"prerelease={'true' if prerelease else 'false'}")
    print(f"files={len(paths)}")
    print(f"source_sha256={fingerprint}")
    print("public source gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
