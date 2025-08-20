#!/usr/bin/env python3
"""
Generate Cloudflare rule expression files from an ASN CSV and a template (environment-driven; no CLI flags).

Inputs:
- CSV with columns: ASN, Name, enable, action
- Template file containing a placeholder token, default: `{%ASNS%}`
  Example template (`rule-template.wf`):
    (ip.src.asnum in {%ASNS%} and not cf.client.bot)

Behavior:
- By default uses only rows with enable == TRUE (case-insensitive).
- Allowed actions: js_challenge, managed_challenge, interactive_challenge, block.
- If an ASN appears multiple times, the last row's (enable, action) takes precedence (last-wins).
- De-duplicates ASNs per action and sorts them numerically.
- Packs ASNs into multiple rules per action so that each rendered expression length <= Cloudflare's limit.
- Cleans existing generated files matching rule-*.wf in the output directory before writing new ones.

Configuration (from environment; local dev also loads .env if present):
- ASN_CSV        Path to CSV (default: asn.csv)
- RULE_TEMPLATE  Path to template file (default: rule-template.wf)
- RULES_DIR      Directory to write .wf files (default: rules)
- MAX_RULE_CHARS Max characters allowed per rule expression (default: Cloudflare max; must be <= 4096)

Usage:
  python3 scripts/generate_rules.py
"""
from __future__ import annotations
import csv
from pathlib import Path
from typing import Iterable, List, Dict, Tuple
from util_env import load_default_env, get_optional, get_int

# Cloudflare documented maximum rule expression length
# https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/
CLOUDFLARE_MAX_EXPR_CHARS = 4096

# Prescriptive defaults (not configurable)
PLACEHOLDER_TOKEN = "{%ASNS%}"
PREFIX_AS = False  # ip.src.asnum expects numeric ASNs (no 'AS' prefix)
ALLOWED_ACTIONS = {"js_challenge", "managed_challenge", "interactive_challenge", "block"}


def normalize_enable(v: str | None) -> str | None:
    if v is None:
        return None
    return v.strip().upper()


def normalize_action(v: str | None) -> str:
    return (v or "").strip().lower()


def read_asns_by_action(csv_path: Path) -> Dict[str, List[int]]:
    """Return mapping action -> ASNs using last-wins on (enable, action).

    - Only rows with enable in {TRUE, FALSE} are considered. Others ignored.
    - If an ASN appears multiple times, the last occurrence's pair (enable, action) is used.
    - Rows with enable TRUE must have action in ALLOWED_ACTIONS; otherwise error.
    - Disabled rows (enable FALSE) may have any action; they end up excluded.
    """
    last: Dict[int, Tuple[bool, str]] = {}
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        required = {"ASN", "Name", "enable", "action"}
        missing = required - set(rdr.fieldnames or [])
        if missing:
            raise SystemExit(
                f"CSV is missing required columns: {', '.join(sorted(missing))}. Found: {rdr.fieldnames}"
            )
        for i, r in enumerate(rdr, start=2):
            v = (r.get("ASN") or "").strip()
            try:
                asn = int(v)
            except Exception:
                raise SystemExit(f"Non-integer ASN at line {i}: '{v}' (Name={r.get('Name')})")
            en = normalize_enable(r.get("enable"))
            if en not in {"TRUE", "FALSE"}:
                # Ignore invalid enable values
                continue
            act = normalize_action(r.get("action"))
            last[asn] = (en == "TRUE", act)

    # Build groups
    groups: Dict[str, List[int]] = {a: [] for a in sorted(ALLOWED_ACTIONS)}
    for asn, (enabled, action) in last.items():
        if not enabled:
            continue
        if action not in ALLOWED_ACTIONS:
            raise SystemExit(
                f"Enabled ASN {asn} has invalid action '{action}'. Allowed: {sorted(ALLOWED_ACTIONS)}"
            )
        groups[action].append(asn)
    return groups


def dedup_preserve_order(values: Iterable[int]) -> List[int]:
    seen = set()
    out: List[int] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def pack_by_char_limit(
    asns: List[int], tpl: str, placeholder: str, prefix_as: bool, max_chars: int
) -> List[str]:
    """Pack ASNs into multiple rule contents such that each content length <= max_chars.

    Returns a list of fully rendered rule strings (template with placeholder replaced).
    """
    def render(lst: List[int]) -> str:
        inside = build_set_content(lst, prefix_as=prefix_as)
        replacement = f"{{{inside}}}" if ("{" in placeholder or "}" in placeholder) else inside
        return tpl.replace(placeholder, replacement)

    out: List[str] = []
    cur: List[int] = []
    for n in asns:
        if not cur:
            cur = [n]
            content = render(cur)
            if len(content) > max_chars:
                raise SystemExit(
                    f"Single ASN {n} produces a rule longer than max-chars={max_chars}. "
                    f"Consider reducing template size or increasing limit."
                )
            continue
        test = cur + [n]
        content = render(test)
        if len(content) <= max_chars:
            cur.append(n)
        else:
            out.append(render(cur))
            cur = [n]
            content = render(cur)
            if len(content) > max_chars:
                raise SystemExit(
                    f"Single ASN {n} produces a rule longer than max-chars={max_chars}. "
                    f"Consider reducing template size or increasing limit."
                )
    if cur:
        out.append(render(cur))
    return out


def build_set_content(asns: List[int], prefix_as: bool) -> str:
    # Cloudflare ruleset supports sets with braces and space-separated elements.
    # This returns the inside of the braces (space-separated ASNs) without wrapping braces.
    if prefix_as:
        return " ".join(f"AS{n}" for n in asns)
    return " ".join(str(n) for n in asns)


def main() -> None:
    load_default_env()
    csv_path = Path(get_optional("ASN_CSV", "asn.csv"))
    tpl_path = Path(get_optional("RULE_TEMPLATE", "rule-template.wf"))
    out_dir = Path(get_optional("RULES_DIR", "rules"))
    max_chars = get_int("MAX_RULE_CHARS", CLOUDFLARE_MAX_EXPR_CHARS)

    if max_chars > CLOUDFLARE_MAX_EXPR_CHARS:
        raise SystemExit(
            f"MAX_RULE_CHARS {max_chars} exceeds Cloudflare's maximum of {CLOUDFLARE_MAX_EXPR_CHARS}. "
            f"Provide a value <= {CLOUDFLARE_MAX_EXPR_CHARS}."
        )

    if not csv_path.exists():
        raise SystemExit(f"CSV file not found: {csv_path}")
    if not tpl_path.exists():
        raise SystemExit(f"Template file not found: {tpl_path}")

    groups = read_asns_by_action(csv_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    # Clean existing generated files first (rule-*.wf)
    for old in out_dir.glob("rule-*.wf"):
        try:
            old.unlink()
        except Exception:
            # Ignore file removal errors to avoid aborting generation
            pass

    tpl = tpl_path.read_text(encoding="utf-8")
    if PLACEHOLDER_TOKEN not in tpl:
        raise SystemExit(f"Placeholder '{PLACEHOLDER_TOKEN}' not found in template {tpl_path}")

    total_written = 0

    for action, asns in groups.items():
        asns = dedup_preserve_order(asns)
        asns = sorted(asns)
        if not asns:
            continue
        contents = pack_by_char_limit(
            asns=asns,
            tpl=tpl,
            placeholder=PLACEHOLDER_TOKEN,
            prefix_as=PREFIX_AS,
            max_chars=max_chars,
        )
        for idx, content in enumerate(contents, start=1):
            out_path = out_dir / f"rule-{action}-{idx}.wf"
            out_path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")
            total_written += 1
            print(f" - wrote {out_path}")

    if total_written == 0:
        raise SystemExit("No ASNs to write for any action. Check your CSV contents.")
    print(f"Wrote {total_written} file(s) across actions: {', '.join(a for a, lst in groups.items() if lst)}")


if __name__ == "__main__":
    main()
