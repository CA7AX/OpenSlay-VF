from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import openslay_rng_verifier
from openslay_rng_verifier.rules import descriptor_hash


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_MODULES = ("openslay", "openslay_server", "game_mode")
PROTOCOL_V2_VECTOR_SHA256 = "1db756ddcaa67cabe624f694203bf3e5ca516cd630c6aeda16cdb1152d30ebc7"


def is_forbidden(module: str) -> bool:
    return any(module == name or module.startswith(f"{name}.") for name in FORBIDDEN_MODULES)


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
