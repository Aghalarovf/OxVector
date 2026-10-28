import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Pattern, Set
from core.models import HttpRecord, Finding

DEFAULT_LEAKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leaks.json")
MAX_VALUE_LENGTH = 200
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class LeakRule:
    title: str
    headers: List[str]
    severity: str
    hint: str
    pattern: Optional[Pattern] = None
    evidence: str = "{header}: {value}"
    ignore: Set[str] = field(default_factory=set)

    @property
    def wildcard(self) -> bool:
        return "*" in self.headers


def _build_rule(raw: dict) -> Optional[LeakRule]:
    if not isinstance(raw, dict):
        return None
    headers = [str(h).lower() for h in raw.get("headers", []) if h]
    title = raw.get("title")
    severity = str(raw.get("severity", "low")).lower()
    if not headers or not title or severity not in VALID_SEVERITIES:
        return None
    pattern = None
    if raw.get("pattern"):
        try:
            pattern = re.compile(raw["pattern"], re.IGNORECASE)
        except re.error:
            return None
    return LeakRule(
        title=title,
        headers=headers,
        severity=severity,
        hint=raw.get("hint", ""),
        pattern=pattern,
        evidence=raw.get("evidence") or "{header}: {value}",
        ignore={str(h).lower() for h in raw.get("ignore_headers", [])},
    )


def load_rules(path: Optional[str] = None) -> List[LeakRule]:
    target = path or DEFAULT_LEAKS_PATH
    try:
        with open(target, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"  [warning] could not load {target}: {exc}", file=sys.stderr)
        return []
    entries = data.get("rules", []) if isinstance(data, dict) else data
    rules = []
    for raw in entries or []:
        rule = _build_rule(raw)
        if rule:
            rules.append(rule)
    return rules


def _render(template: str, header: str, value: str, match: str) -> str:
    return (
        template.replace("{header}", header)
        .replace("{value}", value)
        .replace("{match}", match)
    )


class InfoDisclosureHeaderLeakDetector:
    def __init__(self, leaks_path: Optional[str] = None):
        self.rules = load_rules(leaks_path)

    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        headers = {
            str(k).lower(): v if isinstance(v, str) else str(v)
            for k, v in (record.response.headers or {}).items()
        }
        url = record.request.url

        for rule in self.rules:
            names = list(headers) if rule.wildcard else rule.headers
            for name in names:
                if name in rule.ignore:
                    continue
                value = headers.get(name)
                if value is None or (not value and rule.pattern is None and not rule.wildcard):
                    continue
                match_text = ""
                if rule.pattern is not None:
                    match = rule.pattern.search(value)
                    if not match:
                        continue
                    match_text = match.group(0)
                elif rule.wildcard:
                    continue
                shown = value[:MAX_VALUE_LENGTH]
                findings.append(Finding(
                    module="info_disclosure",
                    severity=rule.severity,
                    title="Information Disclosure: " + _render(rule.title, name, shown, match_text),
                    location=url,
                    evidence=_render(rule.evidence, name, shown, match_text),
                    vector_hint=rule.hint or None,
                ))
        return findings