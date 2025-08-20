#!/usr/bin/env python3
"""
Unified environment loader for local dev (.env) and CI (real env).

Behavior:
- If ENV_FILE is set, load that file first (non-overriding).
- Else, if .env exists in current working directory, load it (non-overriding).
- All getters return values from os.environ after loading.
- No overrides: explicit environment variables always take precedence over .env.

Helpers:
- load_default_env()
- get_required(name: str) -> str
- get_optional(name: str, default: str | None = None) -> str | None
- get_int(name: str, default: int) -> int
"""
from __future__ import annotations
import os
from pathlib import Path


def _unquote(v: str) -> str:
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        v = v[1:-1]
    return v


def load_env_file(path: Path) -> None:
    if not path or not path.exists():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            # Remove inline comment if unquoted
            if not (val.startswith("'") and val.endswith("'")) and not (val.startswith('"') and val.endswith('"')):
                hash_idx = val.find(" #")
                if hash_idx != -1:
                    val = val[:hash_idx].rstrip()
            val = _unquote(val)
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception:
        # best-effort: ignore dotenv errors
        pass


def load_default_env() -> None:
    env_file = os.environ.get("ENV_FILE")
    if env_file:
        load_env_file(Path(env_file))
        return
    # fallback: .env in cwd
    p = Path.cwd() / ".env"
    if p.exists():
        load_env_file(p)


def get_required(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise SystemExit(f"Required environment variable not set: {name}")
    return val


def get_optional(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def get_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    try:
        return int(v)
    except Exception:
        raise SystemExit(f"Environment variable {name} must be an integer, got: {v}")


def get_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    val = v.strip().lower()
    if val in {"1", "true", "yes", "y", "on"}:
        return True
    if val in {"0", "false", "no", "n", "off"}:
        return False
    raise SystemExit(f"Environment variable {name} must be a boolean (true/false), got: {v}")
