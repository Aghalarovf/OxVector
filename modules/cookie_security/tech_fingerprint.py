import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple
from core.models import HttpRecord, Finding
from core.http_utils import parse_set_cookies, parse_cookie_header, url_host

DEFAULT_SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json")


@dataclass
class Signature:
    name: str
    category: str
    implies: List[str] = field(default_factory=list)
    cookies: List[Tuple[Pattern, Optional[Pattern]]] = field(default_factory=list)


def _compile(pattern: str) -> Pattern:
    return re.compile(pattern, re.IGNORECASE)


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _build_signature(raw: dict) -> Optional[Signature]:
    name = raw.get("name")
    if not name:
        return None
    sig = Signature(name=name, category=raw.get("category", "Unknown"), implies=_as_list(raw.get("implies")))
    try:
        for name_pattern, value_pattern in (raw.get("cookies") or {}).items():
            sig.cookies.append((_compile(name_pattern), _compile(value_pattern) if value_pattern else None))
    except re.error:
        return None
    return sig


def load_signatures(path: Optional[str] = None) -> List[Signature]:
    target = path or DEFAULT_SIGNATURES_PATH
    try:
        with open(target, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    entries = data.get("technologies", []) if isinstance(data, dict) else data
    signatures = []
    for raw in entries or []:
        if isinstance(raw, dict):
            sig = _build_signature(raw)
            if sig:
                signatures.append(sig)
    return signatures


class TechFingerprintAnalyzer:
    def __init__(self, signatures_path: Optional[str] = None):
        self.signatures = load_signatures(signatures_path)
        self.by_name: Dict[str, Signature] = {s.name: s for s in self.signatures}

    def _hit(self, found: dict, sig: Signature, signal: str, evidence: str, url: str, cookie_name: Optional[str] = None):
        entry = found.setdefault(sig.name, {
            "signals": set(), "evidence": [], "url": url, "implied_by": set(), "cookie_names": set(),
        })
        entry["signals"].add(signal)
        entry["evidence"].append(evidence)
        if signal == "cookie" and cookie_name is not None:
            entry["cookie_names"].add(cookie_name.lower())

    def _scan_record(self, record: HttpRecord, found: dict):
        resp = record.response
        url = record.request.url
        headers = {
            str(k).lower(): (v if isinstance(v, str) else str(v))
            for k, v in (resp.headers or {}).items()
        }
        cookies = [("Set-Cookie", c["name"], c["value"]) for c in parse_set_cookies(headers.get("set-cookie", ""))]
        request_headers = {str(k).lower(): v for k, v in (record.request.headers or {}).items()}
        cookies.extend(
            ("Cookie", n, v)
            for n, v in parse_cookie_header(request_headers.get("cookie", "") if isinstance(request_headers.get("cookie", ""), str) else "").items()
        )

        for sig in self.signatures:
            if not sig.cookies:
                continue
            for origin, cookie_name, cookie_value in cookies:
                for name_rx, value_rx in sig.cookies:
                    if not name_rx.search(cookie_name):
                        continue
                    if value_rx is not None and not value_rx.search(cookie_value):
                        continue
                    # one hit per cookie, even if several patterns of the same signature match it
                    self._hit(found, sig, "cookie", f"{origin} {cookie_name}", url, cookie_name)
                    break

    def _apply_implications(self, found: dict):
        queue = list(found.keys())
        while queue:
            current = queue.pop()
            sig = self.by_name.get(current)
            if not sig:
                continue
            for implied in sig.implies:
                target = self.by_name.get(implied)
                if not target:
                    continue
                is_new = implied not in found
                self._hit(found, target, "implied", f"implied by {current}", found[current]["url"])
                found[implied]["implied_by"].add(current)
                if is_new:
                    queue.append(implied)

    def analyze_all(self, records: List[HttpRecord]) -> List[Finding]:
        # Each request is fingerprinted on its own; nothing is merged across requests or hosts.
        findings = []
        for index, record in enumerate(records):
            found: dict = {}
            try:
                self._scan_record(record, found)
            except Exception:
                continue
            if not found:
                continue
            self._apply_implications(found)
            host = url_host(record.request.url) or record.request.url
            for name in sorted(found, key=lambda n: (self.by_name[n].category, n)):
                entry = found[name]
                sig = self.by_name[name]
                confirmed = len(entry["cookie_names"]) >= 2
                findings.append(Finding(
                    module="cookie_security",
                    severity="info",
                    title=f"Tech Fingerprint: {name} ({sig.category})",
                    location=entry["url"],
                    evidence="; ".join(entry["evidence"]),
                    vector_hint=None,
                    confidence="confirmed" if confirmed else "candidate",
                    extra={
                        "host": host,
                        "technology": name,
                        "category": sig.category,
                        "signals": sorted(entry["signals"]),
                        "implied_by": sorted(entry["implied_by"]),
                        "request_index": index,
                    },
                ))
        return findings