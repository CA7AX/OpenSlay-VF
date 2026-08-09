#!/usr/bin/env python3
"""Audit, install, and checksum verifier wheel and source distributions."""

from __future__ import annotations

import argparse
import ast
import email.parser
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PACKAGE_FILES = {
    "__init__.py",
    "__main__.py",
    "cli.py",
    "data/openslay-prototype-v1.partial.json",
    "data/prototype-deck-v1.json",
    "localization.py",
    "operations.py",
    "oracle.py",
    "protocol.py",
    "README.md",
    "README.zh-CN.md",
    "rules.py",
    "SPEC.md",
    "SPEC.zh-CN.md",
    "test-vectors/protocol-v2.json",
    "verifier.py",
    "witness.py",
}
FORBIDDEN_COMPONENTS = {".git", "__pycache__", "openslay", "openslay_server", "game_mode"}
EXPECTED_OPTIONAL_DEPENDENCIES = {
    'build==1.5.0; extra == "release"',
    'pytest<10,>=7; extra == "test"',
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"distribution audit failed: {message}")


def package_version() -> str:
    tree = ast.parse((ROOT / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    fail("cannot read package version")


def safe_parts(rendered: str) -> tuple[str, ...]:
    path = PurePosixPath(rendered)
    if path.is_absolute() or ".." in path.parts or any(part in FORBIDDEN_COMPONENTS for part in path.parts):
        fail(f"unsafe or private archive member: {rendered}")
    return path.parts


def audit_wheel(wheel: Path, version: str) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        for info in archive.infolist():
            safe_parts(info.filename)
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type == 0o120000:
                fail(f"wheel contains a symlink: {info.filename}")
        missing = {
            f"openslay_rng_verifier/{relative}" for relative in REQUIRED_PACKAGE_FILES
        } - names
        if missing:
            fail("wheel is missing package files: " + ", ".join(sorted(missing)))
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata_names) != 1 or len(entry_names) != 1:
            fail("wheel must contain exactly one METADATA and entry_points.txt")
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_names[0]))
        if metadata.get("Name") != "openslay-rng-verifier":
            fail("wheel project name is incorrect")
        if metadata.get("Version") != version:
            fail("wheel version differs from __version__")
        if metadata.get("Requires-Python") != ">=3.10":
            fail("wheel Requires-Python differs from the public contract")
        if metadata.get("License-Expression") != "MIT" and metadata.get("License") != "MIT":
            fail("wheel license metadata is not MIT")
        if set(metadata.get_all("Provides-Extra", [])) != {"release", "test"}:
            fail("wheel optional dependency groups differ from the release contract")
        if set(metadata.get_all("Requires-Dist", [])) != EXPECTED_OPTIONAL_DEPENDENCIES:
            fail("wheel dependencies differ from the release contract")
        entries = archive.read(entry_names[0]).decode("utf-8")
        if "openslay-rng-verify = openslay_rng_verifier.cli:main" not in entries:
            fail("wheel console entry point is missing or changed")


def audit_sdist(sdist: Path) -> None:
    required = {
        "LICENSE",
        "README.md",
        "README.zh-CN.md",
        "SPEC.md",
        "SPEC.zh-CN.md",
        "pyproject.toml",
        "data/prototype-deck-v1.json",
        "test-vectors/protocol-v2.json",
        "tests/test_standalone.py",
    }
    with tarfile.open(sdist, "r:gz") as archive:
        relative_names: set[str] = set()
        for member in archive.getmembers():
            parts = safe_parts(member.name)
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                fail(f"sdist contains a link or special member: {member.name}")
            if len(parts) > 1:
                relative_names.add(PurePosixPath(*parts[1:]).as_posix())
        missing = required - relative_names
        if missing:
            fail("sdist is missing source files: " + ", ".join(sorted(missing)))


def install_and_smoke_test(wheel: Path, sdist: Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="openslay-verifier-install-") as temporary:
        root = Path(temporary)
        target = root / "site"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-compile",
                "--no-deps",
                "--target",
                str(target),
                str(wheel),
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            fail(f"isolated wheel install failed: {completed.stderr.strip()}")
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(target)
        code = (
            "import json, openslay_rng_verifier as v; "
            "print(json.dumps({'version': v.__version__, "
            "'rules': v.load_ruleset('bundled')['ruleset_id']}))"
        )
        imported = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        expected = {"version": version, "rules": "openslay-prototype-v1-partial"}
        try:
            imported_payload = json.loads(imported.stdout)
        except json.JSONDecodeError:
            imported_payload = None
        if imported.returncode != 0 or imported_payload != expected:
            fail(f"isolated import failed: {imported.stdout.strip()} {imported.stderr.strip()}")
        cli = subprocess.run(
            [sys.executable, "-m", "openslay_rng_verifier", "--version"],
            cwd=root,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="strict",
            capture_output=True,
            check=False,
        )
        if cli.returncode != 0 or cli.stdout.strip() != f"openslay-rng-verify {version}":
            fail(f"isolated CLI failed: {cli.stdout.strip()} {cli.stderr.strip()}")

        source_root = root / "source"
        source_root.mkdir()
        with tarfile.open(sdist, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                safe_parts(member.name)
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    fail(f"sdist contains a link or special member: {member.name}")
            archive.extractall(source_root, members=members)
        extracted = next(path for path in source_root.iterdir() if path.is_dir())
        renamed = source_root / "sdist-source"
        extracted.rename(renamed)
        extracted = renamed
        tests = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", str(extracted / "tests")],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if tests.returncode != 0:
            fail(f"installed-wheel tests failed:\n{tests.stdout}\n{tests.stderr}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    return parser.parse_args()


def main() -> int:
    directory = parse_args().directory.resolve()
    version = package_version()
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    unexpected = sorted(
        path.name for path in directory.iterdir() if path.is_file() and path.suffix not in {".whl", ".gz"}
    )
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        fail(
            f"expected exactly one wheel and one sdist; found wheels={wheels}, "
            f"sdists={sdists}, unexpected={unexpected}"
        )
    normalized = version.replace("-", "_").replace("+", "_")
    if not wheels[0].name.startswith(f"openslay_rng_verifier-{normalized}-"):
        fail("wheel filename does not match the package version")
    if sdists[0].name not in {
        f"openslay_rng_verifier-{normalized}.tar.gz",
        f"openslay-rng-verifier-{normalized}.tar.gz",
    }:
        fail("sdist filename does not match the package version")

    audit_wheel(wheels[0], version)
    audit_sdist(sdists[0])
    install_and_smoke_test(wheels[0], sdists[0], version)
    checksum_path = directory / "SHA256SUMS"
    with checksum_path.open("w", encoding="utf-8", newline="\n") as stream:
        for artifact in (*wheels, *sdists):
            stream.write(f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {artifact.name}\n")
    print("distribution audit passed")
    print(checksum_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
