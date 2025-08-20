#!/usr/bin/env python3
"""
Sync WAF custom rules in Cloudflare from local files in rules/ (environment-driven; no CLI flags).

Prescriptive behavior:
- Manage ONLY rules whose description starts with one of:
  [AUTO] JS Challenge ASN - , [AUTO] Managed Challenge ASN - , [AUTO] Interactive Challenge ASN - , [AUTO] Block ASN -
- Local expressions are read from rules/rule-<action>-<N>.wf where <action> in
  {js_challenge, managed_challenge, interactive_challenge, block}.
  Legacy files rules/rule-<N>.wf are treated as js_challenge.
- Action is taken from the filename's action and mapped to Cloudflare action names
  (interactive_challenge -> challenge; others map 1:1).
- Any remotely-managed rule with one of the prefixes but missing locally will be deleted.
- Other custom rules (without the prefixes) are preserved untouched and keep order.

Configuration (from environment; local dev also loads .env if present via util_env):
- CLOUDFLARE_API_TOKEN  API token with Zone -> Zone WAF -> Edit (optionally also Read) (required)
- CLOUDFLARE_ZONE_ID    Cloudflare Zone ID (required)
- RULES_DIR             Directory containing rule-*.wf (default: rules)
- DRY_RUN               true/false to print plan only (default: false)

References:
- Rulesets API, entrypoint phase http_request_firewall_custom
  GET  /zones/:zone_id/rulesets/phases/http_request_firewall_custom/entrypoint
  PUT  /zones/:zone_id/rulesets/phases/http_request_firewall_custom/entrypoint
  Docs: https://developers.cloudflare.com/waf/custom-rules/create-api/
        https://developers.cloudflare.com/ruleset-engine/rules-language/actions/
        https://developers.cloudflare.com/ruleset-engine/basic-operations/add-rule-phase-rulesets/
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib import request, error
from util_env import load_default_env, get_required, get_optional, get_bool

PHASE = "http_request_firewall_custom"
ALLOWED_ACTIONS = {"js_challenge", "managed_challenge", "interactive_challenge", "block"}
ACTION_TO_CF = {
    "js_challenge": "js_challenge",
    "managed_challenge": "managed_challenge",
    "interactive_challenge": "challenge",  # interactive
    "block": "block",
}
DESC_PREFIXES = {
    "js_challenge": "[AUTO] JS Challenge ASN - ",
    "managed_challenge": "[AUTO] Managed Challenge ASN - ",
    "interactive_challenge": "[AUTO] Interactive Challenge ASN - ",
    "block": "[AUTO] Block ASN - ",
}


@dataclass
class Rule:
    id: Optional[str]
    action: str
    expression: str
    description: Optional[str]
    enabled: bool = True

    def to_payload(self) -> Dict:
        d = {
            "action": self.action,
            "expression": self.expression,
            "enabled": self.enabled,
        }
        if self.description is not None:
            d["description"] = self.description
        if self.id is not None:
            d["id"] = self.id  # Including id updates the existing rule
        return d


class CFClient:
    def __init__(self, token: str, zone_id: str):
        self.token = token
        self.zone_id = zone_id
        self.base = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"

    def _req(self, method: str, url: str, body: Optional[Dict] = None) -> Tuple[int, Dict]:
        data = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req) as resp:
                status = resp.getcode()
                text = resp.read().decode("utf-8")
                return status, json.loads(text) if text else {}
        except error.HTTPError as e:
            status = e.code
            text = e.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = {"raw": text}
            return status, parsed

    def get_entrypoint(self) -> Tuple[Optional[str], List[Dict]]:
        url = f"{self.base}/phases/{PHASE}/entrypoint"
        status, obj = self._req("GET", url)
        if status == 404:
            return None, []
        if status != 200 or not obj.get("success", False):
            raise SystemExit(f"Failed to GET entrypoint: {status} {obj}")
        res = obj.get("result", {})
        return res.get("id"), res.get("rules", []) or []

    def put_entrypoint_rules(self, rules_payload: List[Dict]) -> Dict:
        url = f"{self.base}/phases/{PHASE}/entrypoint"
        status, obj = self._req("PUT", url, {"rules": rules_payload})
        if status not in (200, 201) or not obj.get("success", False):
            raise SystemExit(f"Failed to PUT entrypoint rules: {status} {obj}")
        return obj


def natural_key(s: str) -> Tuple:
    return tuple(int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s))


def load_local_rules(rules_dir: Path) -> Dict[str, Rule]:
    files = sorted(rules_dir.glob("rule-*.wf"), key=lambda p: natural_key(p.name))
    local: Dict[str, Rule] = {}
    for p in files:
        expr = p.read_text(encoding="utf-8").strip()
        if not expr:
            continue
        m_new = re.match(r"rule-([a-z_]+)-(\d+)\.wf$", p.name)
        m_legacy = re.match(r"rule-(\d+)\.wf$", p.name)
        if m_new:
            action = m_new.group(1).lower()
            index = int(m_new.group(2))
            if action not in ALLOWED_ACTIONS:
                # Skip unknown action files to avoid accidental uploads
                continue
        elif m_legacy:
            action = "js_challenge"
            index = int(m_legacy.group(1))
        else:
            # Skip non-conforming names
            continue
        cf_action = ACTION_TO_CF[action]
        desc = f"{DESC_PREFIXES[action]}{index}"
        local[desc] = Rule(id=None, action=cf_action, expression=expr, description=desc, enabled=True)
    return local


def _is_managed(desc: Optional[str]) -> bool:
    if not isinstance(desc, str):
        return False
    return any(desc.startswith(prefix) for prefix in DESC_PREFIXES.values())


def partition_remote_rules(remote_rules: List[Dict]) -> Tuple[Dict[str, Rule], List[Dict]]:
    managed: Dict[str, Rule] = {}
    others: List[Dict] = []
    for r in remote_rules:
        desc = r.get("description")
        if _is_managed(desc):
            rule = Rule(
                id=r.get("id"),
                action=r.get("action"),
                expression=r.get("expression", ""),
                description=desc,
                enabled=bool(r.get("enabled", True)),
            )
            managed[desc] = rule
        else:
            # Preserve essential fields for non-managed rules, including action_parameters
            payload: Dict = {
                "id": r.get("id"),
                "action": r.get("action"),
                "expression": r.get("expression", ""),
                "description": r.get("description"),
                "enabled": bool(r.get("enabled", True)),
            }
            if r.get("action_parameters") is not None:
                payload["action_parameters"] = r.get("action_parameters")
            others.append(payload)
    return managed, others


@dataclass
class Plan:
    to_add: List[Rule]
    to_update: List[Tuple[Rule, Rule]]  # (old, new)
    to_delete: List[Rule]
    final_rules_payload: List[Dict]


def build_plan(existing_managed: Dict[str, Rule], other_rules: List[Dict], local: Dict[str, Rule]) -> Plan:
    # Determine add/update/delete by description key
    to_add: List[Rule] = []
    to_update: List[Tuple[Rule, Rule]] = []
    to_delete: List[Rule] = []

    # Updates and additions
    for desc, new_rule in local.items():
        if desc in existing_managed:
            old = existing_managed[desc]
            # Preserve id; force desired action/expr/enabled/description
            updated = Rule(
                id=old.id,
                action=new_rule.action,
                expression=new_rule.expression,
                description=desc,
                enabled=True,
            )
            # Only mark as update if something actually differs
            if (old.action != updated.action) or (old.expression.strip() != updated.expression.strip()) or (not old.enabled):
                to_update.append((old, updated))
            # Replace in map to reflect target state
            existing_managed[desc] = updated
        else:
            to_add.append(new_rule)
            existing_managed[desc] = new_rule

    # Deletions: remote managed not present locally
    for desc, old in list(existing_managed.items()):
        if desc not in local:
            to_delete.append(old)
            existing_managed.pop(desc, None)

    # Build final payload: keep other rules in original order (preserving action_parameters),
    # then our managed rules ordered by numeric suffix
    managed_rules_sorted = sorted(existing_managed.values(), key=lambda r: natural_key(r.description or ""))
    final_rules_payload = other_rules + [r.to_payload() for r in managed_rules_sorted]

    return Plan(to_add=to_add, to_update=to_update, to_delete=to_delete, final_rules_payload=final_rules_payload)


def _sig(rule: Dict) -> Dict:
    """Extract a stable signature for comparison of non-managed rules."""
    return {
        "id": rule.get("id"),
        "action": rule.get("action"),
        "expression": rule.get("expression", ""),
        "description": rule.get("description"),
        "enabled": bool(rule.get("enabled", True)),
        # Could be None; explicitly include to detect accidental drops for actions like skip
        "action_parameters": rule.get("action_parameters"),
    }


def enforce_prefix_guard(remote_rules: List[Dict], final_rules_payload: List[Dict]) -> None:
    """Abort if any non-prefixed (manual) rule would change or go missing.

    - We compare by rule id when available; otherwise by the signature itself.
    - Order is NOT enforced; only content equality for the preserved fields.
    """
    remote_manual = [r for r in remote_rules if not _is_managed(r.get("description"))]
    final_manual = [r for r in final_rules_payload if not _is_managed(r.get("description"))]

    # Build maps by id (or by signature when id absent)
    def key(rule: Dict) -> Tuple:
        rid = rule.get("id")
        if rid is not None:
            return ("id", rid)
        s = _sig(rule)
        return ("sig", s.get("description"), s.get("expression"), s.get("action"), s.get("enabled"))

    remote_map = {key(r): _sig(r) for r in remote_manual}
    final_map = {key(r): _sig(r) for r in final_manual}

    errors: List[str] = []
    # Missing or changed
    for k, v in remote_map.items():
        if k not in final_map:
            errors.append(f"missing manual rule: {v}")
        elif final_map[k] != v:
            errors.append(f"changed manual rule: before={v} after={final_map[k]}")

    # Unexpected extra non-managed rule from our payload (should never happen)
    for k, v in final_map.items():
        if k not in remote_map:
            errors.append(f"unexpected manual rule in payload: {v}")

    if errors:
        lines = "\n  - ".join(errors)
        raise SystemExit(f"Prefix guard failed; aborting to avoid modifying manual rules:\n  - {lines}")


def main() -> None:
    # Load .env for local dev if present; CI should provide real env
    load_default_env()

    token = get_required("CLOUDFLARE_API_TOKEN")
    zone_id = get_required("CLOUDFLARE_ZONE_ID")
    rules_dir = Path(get_optional("RULES_DIR", "rules"))
    dry_run = get_bool("DRY_RUN", False)
    if not rules_dir.exists():
        raise SystemExit(f"Rules directory not found: {rules_dir}")

    local_rules = load_local_rules(rules_dir)
    if not local_rules:
        raise SystemExit(f"No local rules found in {rules_dir} (expect files like rule-1.wf)")

    cf = CFClient(token=token, zone_id=zone_id)
    ruleset_id, remote_rules = cf.get_entrypoint()

    existing_managed, other_rules = partition_remote_rules(remote_rules)

    plan = build_plan(existing_managed, other_rules, local_rules)

    # Preflight guard: ensure manual (non-prefixed) rules stay identical and present
    enforce_prefix_guard(remote_rules, plan.final_rules_payload)

    print("Planned changes:")
    print(f"  Add:    {len(plan.to_add)}")
    for r in plan.to_add:
        print(f"    + {r.description}")
    print(f"  Update: {len(plan.to_update)}")
    for old, new in plan.to_update:
        changed = []
        if old.action != new.action:
            changed.append("action")
        if old.expression.strip() != new.expression.strip():
            changed.append("expression")
        if not old.enabled and new.enabled:
            changed.append("enabled")
        print(f"    ~ {old.description} ({', '.join(changed)})")
    print(f"  Delete: {len(plan.to_delete)}")
    for r in plan.to_delete:
        print(f"    - {r.description}")

    if dry_run:
        print("Dry run enabled. No changes applied.")
        return

    # Apply by PUTting the complete rules list to the phase entrypoint.
    # This preserves non-managed rules (prefix guard already validated) and
    # replaces managed rules as per plan. New managed rules are appended after
    # all manual rules, maintaining manual order and placing managed at the end.
    obj = cf.put_entrypoint_rules(plan.final_rules_payload)

    # Summarize result
    res = obj.get("result", {})
    print("Sync complete.")
    print(f"Ruleset ID: {res.get('id')}")
    print(f"Phase:      {res.get('phase')}")
    print(f"Total rules now: {len((res.get('rules') or []))}")


if __name__ == "__main__":
    main()
