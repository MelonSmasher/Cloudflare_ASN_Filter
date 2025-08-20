#!/usr/bin/env python3
"""
Validate and summarize ASN CSV file (environment-driven; no CLI flags).

Expected CSV header columns: ASN, Name, enable, action
- ASN: integer
- Name: string
- enable: TRUE or FALSE (case-insensitive)
- action: one of [js_challenge, managed_challenge, interactive_challenge, block]

Configuration (from environment; local dev also loads .env if present):
- ASN_CSV         Path to CSV (default: asn.csv)
- DUP_LIMIT       How many duplicate entries to list (default: 10)
- VALIDATE_JSON   true/false to output JSON instead of text (default: false)

Usage:
  python3 scripts/validate_asn_csv.py
"""
from __future__ import annotations
import csv
import json
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple
from util_env import load_default_env, get_optional, get_int, get_bool


@dataclass
class Analysis:
    total_records: int
    enabled_true: int
    disabled_false: int
    other_enable_values: Dict[str, int]
    per_action_enabled: Dict[str, int]
    unique_asns: int
    duplicate_asn_count: int
    duplicate_asns: List[Tuple[int, int]]  # (asn, occurrences)
    noninteger_asn_rows_count: int
    noninteger_examples: List[Dict[str, str]]
    invalid_action_enabled_rows: List[Dict[str, str]]


def normalize_enable(v: str | None) -> str | None:
    if v is None:
        return None
    return v.strip().upper()


ALLOWED_ACTIONS = {"js_challenge", "managed_challenge", "interactive_challenge", "block"}


def load_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        # Basic header validation
        required = {"ASN", "Name", "enable", "action"}
        missing = required - set(rdr.fieldnames or [])
        if missing:
            raise SystemExit(
                f"CSV is missing required columns: {', '.join(sorted(missing))}. "
                f"Found: {rdr.fieldnames}"
            )
        return list(rdr)


def analyze(rows: List[Dict[str, str]]) -> Analysis:
    true_cnt = sum(1 for r in rows if normalize_enable(r.get("enable")) == "TRUE")
    false_cnt = sum(1 for r in rows if normalize_enable(r.get("enable")) == "FALSE")
    other_enables = Counter(
        normalize_enable(r.get("enable"))
        for r in rows
        if normalize_enable(r.get("enable")) not in {"TRUE", "FALSE"}
    )
    # ASN field checks
    asn_vals: List[int] = []
    nonint: List[Tuple[int, str, str]] = []
    for i, r in enumerate(rows, start=2):  # account for header line number
        v = (r.get("ASN") or "").strip()
        try:
            asn_vals.append(int(v))
        except Exception:
            nonint.append((i, v, r.get("Name") or ""))

    unique_asns = len(set(asn_vals))
    c = Counter(asn_vals)
    dups = sorted(((asn, k) for asn, k in c.items() if k > 1), key=lambda x: (-x[1], x[0]))

    # Per-action enabled counts and invalid action detection (consider last-wins at row granularity is not enforced here; summary is raw rows)
    per_action: Counter[str] = Counter()
    invalid_enabled: List[Dict[str, str]] = []
    for i, r in enumerate(rows, start=2):
        en = normalize_enable(r.get("enable"))
        act = (r.get("action") or "").strip().lower()
        if en == "TRUE":
            if act in ALLOWED_ACTIONS:
                per_action[act] += 1
            else:
                invalid_enabled.append({"line": str(i), "ASN": r.get("ASN") or "", "action": act})

    return Analysis(
        total_records=len(rows),
        enabled_true=true_cnt,
        disabled_false=false_cnt,
        other_enable_values={k if k is not None else "": v for k, v in other_enables.items()},
        unique_asns=unique_asns,
        duplicate_asn_count=len(dups),
        duplicate_asns=dups,
        noninteger_asn_rows_count=len(nonint),
        noninteger_examples=[{"line": str(i), "ASN": a, "Name": n} for i, a, n in nonint[:5]],
        per_action_enabled=dict(per_action),
        invalid_action_enabled_rows=invalid_enabled,
    )


def print_human(a: Analysis, dup_limit: int = 10) -> None:
    print(f"Total records: {a.total_records}")
    print(f"Enabled TRUE: {a.enabled_true}")
    print(f"Disabled FALSE: {a.disabled_false}")
    if a.other_enable_values:
        print(f"Other enable values: {a.other_enable_values}")
    else:
        print("Other enable values: {}")
    print(f"Unique ASNs: {a.unique_asns}")
    print(f"Duplicate ASN count: {a.duplicate_asn_count}")
    if a.duplicate_asns:
        print("Top duplicates (asn, occurrences):")
        for asn, k in a.duplicate_asns[:dup_limit]:
            print(f"  {asn}, {k}")
    print(f"Non-integer ASN rows count: {a.noninteger_asn_rows_count}")
    if a.noninteger_examples:
        print("Examples of non-integer ASN rows:")
        for ex in a.noninteger_examples:
            print(f"  line {ex['line']}: ASN='{ex['ASN']}' Name='{ex['Name']}'")
    if a.per_action_enabled:
        print("Enabled rows by action:")
        for k in sorted(a.per_action_enabled.keys()):
            print(f"  {k}: {a.per_action_enabled[k]}")
    if a.invalid_action_enabled_rows:
        print("Invalid enabled action rows (must be one of js_challenge, managed_challenge, interactive_challenge, block):")
        for ex in a.invalid_action_enabled_rows[:10]:
            print(f"  line {ex['line']}: ASN='{ex['ASN']}' action='{ex['action']}'")


def main() -> None:
    load_default_env()
    path = Path(get_optional("ASN_CSV", "asn.csv"))
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    rows = load_rows(path)
    analysis = analyze(rows)

    if get_bool("VALIDATE_JSON", False):
        print(json.dumps(asdict(analysis), ensure_ascii=False, indent=2))
    else:
        dup_limit = get_int("DUP_LIMIT", 10)
        print_human(analysis, dup_limit=dup_limit)


if __name__ == "__main__":
    main()
