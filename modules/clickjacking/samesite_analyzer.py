from typing import List
from core.models import HttpRecord, Finding
from core.http_utils import parse_set_cookies, SESSION_COOKIE_RE

VALID_SAMESITE = ("strict", "lax", "none")


class ClickjackingSameSiteAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        headers = record.response.headers or {}
        raw_set_cookie = headers.get("set-cookie", "")
        if not raw_set_cookie:
            return []

        url = record.request.url
        cookies = parse_set_cookies(raw_set_cookie)
        findings = []

        for cookie in cookies:
            name = cookie["name"]
            attrs = cookie["attrs"]
            samesite = attrs.get("samesite", "")
            secure = "secure" in attrs
            is_session = bool(SESSION_COOKIE_RE.search(name))

            if not samesite:
                severity = "medium" if is_session else "low"
                findings.append(Finding(
                    module="clickjacking",
                    severity=severity,
                    title="Cookie Without SameSite Attribute",
                    location=url,
                    evidence=f"Set-Cookie: {name} has no SameSite attribute",
                    vector_hint="Without an explicit SameSite attribute the cookie's cross-site behavior depends on the browser's default policy, which can enable CSRF",
                    extra={
                        "issue": "missing",
                        "headers": ["Set-Cookie: SameSite"],
                        "cookie": name,
                        "reason": f"Missing: SameSite attribute on cookie '{name}'" + (" (session cookie)" if is_session else ""),
                    },
                ))
                continue

            value = samesite.lower()

            if value not in VALID_SAMESITE:
                severity = "medium" if is_session else "low"
                findings.append(Finding(
                    module="clickjacking",
                    severity=severity,
                    title="Cookie Has Invalid SameSite Value",
                    location=url,
                    evidence=f"Set-Cookie: {name}; SameSite={samesite}",
                    vector_hint="Browsers ignore an invalid SameSite value and fall back to their default behavior, which may send the cookie cross-site",
                    extra={
                        "issue": "weak",
                        "headers": ["Set-Cookie: SameSite"],
                        "cookie": name,
                        "reason": f"Weak: cookie '{name}' has invalid SameSite value '{samesite}' (valid: Strict, Lax, None)",
                    },
                ))
                continue

            if value == "none" and not secure:
                findings.append(Finding(
                    module="clickjacking",
                    severity="high",
                    title="Cookie Has SameSite=None Without Secure",
                    location=url,
                    evidence=f"Set-Cookie: {name}; SameSite=None (Secure missing)",
                    vector_hint="Modern browsers reject SameSite=None cookies that lack the Secure attribute; until then the cookie can be sent cross-site over plain HTTP",
                    extra={
                        "issue": "weak",
                        "headers": ["Set-Cookie: SameSite", "Set-Cookie: Secure"],
                        "cookie": name,
                        "reason": f"Weak: cookie '{name}' uses SameSite=None without the Secure attribute",
                    },
                ))
            elif value == "none" and secure:
                severity = "medium" if is_session else "low"
                findings.append(Finding(
                    module="clickjacking",
                    severity=severity,
                    title="Cookie Allows Cross-Site Sending via SameSite=None",
                    location=url,
                    evidence=f"Set-Cookie: {name}; SameSite=None; Secure",
                    vector_hint="SameSite=None permits the cookie on cross-site requests; ensure CSRF tokens or other defenses protect state-changing actions",
                    extra={
                        "issue": "weak",
                        "headers": ["Set-Cookie: SameSite"],
                        "cookie": name,
                        "reason": f"Weak: cookie '{name}' uses SameSite=None, so it is sent on cross-site requests",
                    },
                ))

        return findings