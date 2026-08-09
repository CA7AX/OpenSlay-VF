#!/usr/bin/env python3
"""Build byte-identical wheel/sdist pairs from two clean Git archives."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release build failed: {message}")


def run(arguments: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> None:
    completed = subprocess.run(arguments, cwd=cwd, env=environment, check=False)
    if completed.returncode != 0:
        fail(f"command exited {completed.returncode}: {' '.join(arguments)}")


def git_output(*arguments: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=not binary,
    )
    if completed.returncode != 0:
        error = completed.stderr if isinstance(completed.stderr, str) else completed.stderr.decode("utf-8", "replace")
        fail(f"git {' '.join(arguments)} failed: {error.strip()}")
    return completed.stdout


def safe_extract(archive: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        members = source.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                fail(f"unsafe Git archive member: {member.name}")
            if not (member.isdir() or member.isfile()):
                fail(f"Git archive contains a link or special member: {member.name}")
        source.extractall(destination, members=members)


def hashes(directory: Path) -> dict[str, str]:
    artifacts = sorted(path for path in directory.iterdir() if path.is_file())
    if not artifacts:
        fail(f"build produced no artifacts in {directory}")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts}


def normalize_sdists(directory: Path, epoch: int) -> None:
    for path in directory.glob("*.tar.gz"):
        records: list[tuple[str, int, bool, bytes]] = []
        with tarfile.open(path, "r:gz") as source:
            for member in source.getmembers():
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    fail(f"unsafe sdist member: {member.name}")
                if not (member.isdir() or member.isfile()):
                    fail(f"sdist contains a link or special member: {member.name}")
                payload = b"" if member.isdir() else source.extractfile(member).read()
                records.append((member.name, member.mode, member.isdir(), payload))

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w", format=tarfile.USTAR_FORMAT) as target:
            for name, mode, is_directory, payload in sorted(
                records,
                key=lambda record: record[0].encode("utf-8"),
            ):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
                member.mode = mode
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = epoch
                member.size = 0 if is_directory else len(payload)
                target.addfile(member, None if is_directory else io.BytesIO(payload))

        staging = path.with_suffix(path.suffix + ".normalized")
        with staging.open("wb") as raw_stream:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_stream,
                mtime=epoch,
            ) as compressed:
                compressed.write(tar_stream.getvalue())
        os.replace(staging, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> int:
    output = parse_args().output.resolve()
    if output.exists() and any(output.iterdir()):
        fail(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    archive = git_output("archive", "--format=tar", "HEAD", binary=True)
    assert isinstance(archive, bytes)
    epoch = git_output("show", "-s", "--format=%ct", "HEAD")
    assert isinstance(epoch, str)
    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": "0", "SOURCE_DATE_EPOCH": epoch.strip(), "TZ": "UTC"})

    with tempfile.TemporaryDirectory(prefix="openslay-verifier-build-") as temporary:
        temporary_root = Path(temporary)
        result_directories: list[Path] = []
        for index in (1, 2):
            source = temporary_root / f"source-{index}"
            distribution = temporary_root / f"dist-{index}"
            source.mkdir()
            distribution.mkdir()
            safe_extract(archive, source)
            run(
                [sys.executable, "-m", "build", "--outdir", str(distribution)],
                cwd=source,
                environment=environment,
            )
            normalize_sdists(distribution, int(epoch.strip()))
            result_directories.append(distribution)

        first_hashes = hashes(result_directories[0])
        second_hashes = hashes(result_directories[1])
        if first_hashes != second_hashes:
            fail(f"clean builds are not byte-identical: {first_hashes!r} != {second_hashes!r}")
        for artifact in sorted(result_directories[0].iterdir()):
            shutil.copy2(artifact, output / artifact.name)

    print("reproducible release build passed")
    for name, digest in first_hashes.items():
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
