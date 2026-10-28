import base64
import binascii
import re
from typing import List
from core.models import HttpRecord, Finding
from core.http_utils import SESSION_COOKIE_RE, parse_set_cookies
from urllib.parse import urlparse, parse_qs

SESSION_PARAMS = (
    "jsessionid", "phpsessid", "sessionid", "session_id", "sid", "sessid",
    "aspsessionid", "session", "sessionkey", "cfid", "cftoken",
)


def _readable(value: str) -> bool:
    if value.startswith("eyJ") and value.count(".") == 2:
        return False
    if len(value) < 12 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", value):
        return False
    v = value.replace("-", "+").replace("_", "/")
    v += "=" * (-len(v) % 4)
    try:
        data = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(data) < 8:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) > 0.95


class CookieSecurityValueAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        url = record.request.url

        def add(sev, title, evidence, hint):
            findings.append(Finding(
                module="cookie_security",
                severity=sev,
                title=f"Cookie Security: {title}",
                location=url,
                evidence=evidence,
                vector_hint=hint,
            ))

        for cookie in parse_set_cookies((record.response.headers or {}).get("set-cookie", "")):
            name, value = cookie["name"], cookie["value"]
            if not SESSION_COOKIE_RE.search(name) or not value:
                continue
            if re.fullmatch(r"\d+", value):
                add("medium", "Numeric Session Identifier",
                    f"{name} value is purely numeric ({len(value)} digits)",
                    "Numeric identifiers are often sequential or guessable — collect several and compare")
            elif len(value) < 16:
                add("medium", "Short Session Identifier",
                    f"{name} value is only {len(value)} characters",
                    "Short identifiers have low entropy and can be brute-forced")
            elif _readable(value):
                add("medium", "Session Cookie Value Is Readable Encoded Data",
                    f"{name} base64-decodes to readable text",
                    "Cookie carries client-side state; test tampering, and check for signing and encryption")

        parsed = urlparse(url)
        query_names = {k.lower() for k in parse_qs(parsed.query)}
        leaked = [n for n in SESSION_PARAMS if n in query_names]
        if ";jsessionid=" in url.lower():
            leaked.append("jsessionid (path)")
        if leaked:
            add("medium", "Session ID in URL",
                f"Session identifier in URL: {', '.join(sorted(set(leaked)))}",
                "Session IDs in URLs leak through logs, history and Referer headers and enable fixation")
        return findings