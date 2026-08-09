from __future__ import annotations

import ast
import binascii
import hashlib
import importlib.util
import json
import re
import struct
import zlib
from pathlib import Path

import openslay_rng_verifier
import pytest
from openslay_rng_verifier.rules import descriptor_hash


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_MODULES = ("openslay", "openslay_server", "game_mode")
PROTOCOL_V2_VECTOR_SHA256 = "1db756ddcaa67cabe624f694203bf3e5ca516cd630c6aeda16cdb1152d30ebc7"


def _release_gate():
    spec = importlib.util.spec_from_file_location(
        "test_release_gate", ROOT / "tools" / "release_gate.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = binascii.crc32(chunk_type)
    crc = binascii.crc32(data, crc) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _png(width: int, height: int, *, color_type: int = 6, filter_type: int = 0) -> bytes:
    channels = {2: 3, 6: 4}[color_type]
    row = bytes([filter_type]) + bytes(width * channels)
    header = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(row * height))
        + _png_chunk(b"IEND", b"")
    )


def is_forbidden(module: str) -> bool:
    return any(module == name or module.startswith(f"{name}.") for name in FORBIDDEN_MODULES)


def test_repository_init_supports_top_level_test_collection() -> None:
    spec = importlib.util.spec_from_file_location("__init__", ROOT / "__init__.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = ""
    spec.loader.exec_module(module)

    assert module.__version__ == openslay_rng_verifier.__version__


def test_public_runtime_never_imports_private_game_modules() -> None:
    for path in ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not is_forbidden(alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not is_forbidden(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert ast.unparse(node.func) not in {
                    "sys.path.append",
                    "sys.path.extend",
                    "sys.path.insert",
                    "importlib.import_module",
                    "importlib.util.module_from_spec",
                    "importlib.util.spec_from_file_location",
                }
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "__import__"


def test_public_version_and_protocol_vector_are_explicit() -> None:
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", openslay_rng_verifier.__version__)
    vector = ROOT / "test-vectors" / "protocol-v2.json"
    assert hashlib.sha256(vector.read_bytes()).hexdigest() == PROTOCOL_V2_VECTOR_SHA256
    payload = json.loads(vector.read_text(encoding="utf-8"))
    assert payload["derivation"]["server_secret"] == bytes(range(32)).hex()
    assert payload["derivation"]["client_nonce"] == bytes(range(32, 64)).hex()


def test_bundled_rules_descriptor_is_honestly_partial_and_self_hashed() -> None:
    path = ROOT / "data" / "openslay-prototype-v1.partial.json"
    descriptor = json.loads(path.read_text(encoding="utf-8"))
    assert path.name.endswith(".partial.json")
    assert descriptor["ruleset_id"].endswith("-partial")
    assert descriptor["allow_unlisted_purposes"] is True
    assert descriptor["public_rules_hash"] == descriptor_hash(descriptor)


def test_release_gate_accepts_only_well_formed_branded_readme_pngs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logo = tmp_path / "assets" / "openslay-water-ink-logo.png"
    poster = tmp_path / "assets" / "openslay-water-ink-poster.png"
    logo.parent.mkdir()
    logo.write_bytes(_png(1254, 1254))
    poster.write_bytes(_png(1800, 720, color_type=2))
    gate = _release_gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)

    gate.verify_paths_and_contents(
        [
            "assets/openslay-water-ink-logo.png",
            "assets/openslay-water-ink-poster.png",
        ]
    )


def test_release_gate_rejects_binary_outside_exact_readme_asset_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imposter = tmp_path / "assets" / "almost-the-logo.png"
    imposter.parent.mkdir()
    imposter.write_bytes(_png(1254, 1254))
    gate = _release_gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="binary file is outside the public contract"):
        gate.verify_paths_and_contents(["assets/almost-the-logo.png"])


@pytest.mark.parametrize("failure", ["crc", "zlib", "signature"])
def test_release_gate_rejects_corrupt_or_non_decodable_branded_png(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    logo = tmp_path / "assets" / "openslay-water-ink-logo.png"
    logo.parent.mkdir()
    if failure == "crc":
        payload = bytearray(_png(1254, 1254))
        payload[-20] ^= 0x01
        message = "CRC mismatch"
    elif failure == "zlib":
        header = struct.pack(">IIBBBBB", 1254, 1254, 8, 6, 0, 0, 0)
        payload = (
            b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", header)
            + _png_chunk(b"IDAT", b"not a zlib stream")
            + _png_chunk(b"IEND", b"")
        )
        message = "IDAT stream is not decodable"
    else:
        payload = b"not a PNG"
        message = "signature is missing or corrupt"
    logo.write_bytes(payload)
    gate = _release_gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match=message):
        gate.verify_paths_and_contents(["assets/openslay-water-ink-logo.png"])


@pytest.mark.parametrize(
    ("rendered", "payload", "message"),
    [
        (
            "assets/openslay-water-ink-logo.png",
            _png(1254, 1254, color_type=2),
            "unsupported bit depth/color type",
        ),
        (
            "assets/openslay-water-ink-poster.png",
            _png(960, 960, color_type=2),
            "aspect ratio",
        ),
        (
            "assets/openslay-water-ink-logo.png",
            _png(1254, 1254, filter_type=5),
            "invalid filter",
        ),
    ],
)
def test_release_gate_rejects_wrong_readme_png_shape_mode_or_scanline_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rendered: str,
    payload: bytes,
    message: str,
) -> None:
    path = tmp_path / rendered
    path.parent.mkdir()
    path.write_bytes(payload)
    gate = _release_gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match=message):
        gate.verify_paths_and_contents([rendered])
