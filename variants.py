"""
Edition / type-version resolver.

Detects the *kind* of a technology rather than its numeric version — e.g.
reCAPTCHA v2 / v2 Invisible / v3 / Enterprise, Payflow Pro vs Link, Stripe
Elements vs Checkout, Braintree Drop-in vs Hosted Fields.

Rules live in ``data/variants.json`` (data-driven, easy to extend). Each base
technology maps to an ordered list of variant rules; the first rule whose match
clauses are satisfied by the page evidence wins.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

_DATA = Path(__file__).parent / "data" / "variants.json"

_RULES: Optional[Dict[str, List[Dict[str, Any]]]] = None
_RE_CACHE: Dict[str, "re.Pattern"] = {}

#//* Detection-source suffixes appended elsewhere; preserved across refinement.
_SOURCE_SUFFIXES = (" (pw)", " (deep)")


def _load() -> Dict[str, List[Dict[str, Any]]]:
    global _RULES
    if _RULES is None:
        try:
            with open(_DATA, encoding="utf-8") as f:
                data = json.load(f)
            #//* Drop metadata keys (anything starting with '_').
            _RULES = {k: v for k, v in data.items() if not k.startswith('_')}
        except Exception:
            _RULES = {}
    return _RULES


def _regex(pattern: str) -> "re.Pattern":
    rx = _RE_CACHE.get(pattern)
    if rx is None:
        try:
            rx = re.compile(pattern, re.I)
        except re.error:
            rx = re.compile(r"(?!x)x")  #//* never matches
        _RE_CACHE[pattern] = rx
    return rx


def _rule_matches(rule: Dict[str, Any], ev_lower: str, ev_raw: str) -> bool:
    any_p = rule.get("any")
    re_p = rule.get("re")
    all_p = rule.get("all")
    not_p = rule.get("not")

    #//* If positive clauses are defined, at least one must hit.
    positive_defined = any_p is not None or re_p is not None
    positive_hit = False
    if any_p and any(s.lower() in ev_lower for s in any_p):
        positive_hit = True
    if not positive_hit and re_p:
        positive_hit = any(_regex(p).search(ev_raw) for p in re_p)
    if positive_defined and not positive_hit:
        return False

    if all_p and not all(s.lower() in ev_lower for s in all_p):
        return False
    if not_p and any(s.lower() in ev_lower for s in not_p):
        return False
    return True


def resolve(base_name: str, evidence: str) -> Optional[str]:
    """Return the refined edition label for ``base_name`` given page ``evidence``,
    or None when no rule matches (caller keeps the original name)."""
    rules = _load().get(base_name)
    if not rules:
        return None
    ev_lower = evidence.lower()
    for rule in rules:
        if _rule_matches(rule, ev_lower, evidence):
            return rule.get("label", base_name)
    return None


def refine_label(label: str, evidence: str) -> str:
    """Refine a display label (possibly carrying a ' (pw)'/' (deep)' source tag)
    into its edition variant, preserving the source tag. No-op if nothing matches."""
    suffix = ""
    core = label
    for s in _SOURCE_SUFFIXES:
        if core.endswith(s):
            suffix = s
            core = core[:-len(s)]
            break

    rules = _load()
    #//* Pick the longest base name that prefixes the label (handles "Klarna Checkout").
    candidates = [b for b in rules if core == b or core.startswith(b)]
    if not candidates:
        return label
    base = max(candidates, key=len)
    variant = resolve(base, evidence)
    return (variant + suffix) if variant else label
