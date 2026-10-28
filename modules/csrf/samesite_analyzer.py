from typing import List
from core.models import HttpRecord, Finding
from modules.csrf.common import SESSION_COOKIE_RE, parse_set_cookies


class CsrfSameSiteAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        raw = (record.response.headers or {}).get("set-cookie", "")
        for cookie in parse_set_cookies(raw):
            name = cookie["name"]
            if not SESSION_COOKIE_RE.search(name):
                continue
            attrs = cookie["attrs"]
            samesite = attrs.get("samesite")

            if samesite is None:
                findings.append(Finding(
                    module="csrf",
                    severity="low",
                    title="CSRF: Session Cookie Without SameSite Attribute",
                    location=record.request.url,
                    evidence=f"Set-Cookie: {name} has no SameSite attribute",
                    vector_hint="Behavior depends on browser defaults (Lax-by-default in modern browsers); set SameSite explicitly",
                ))
            elif samesite.lower() == "none":
                findings.append(Finding(
                    module="csrf",
                    severity="medium",
                    title="CSRF: Session Cookie With SameSite=None",
                    location=record.request.url,
                    evidence=f"Set-Cookie: {name}; SameSite=None — sent on all cross-site requests",
                    vector_hint="Cookie is attached to cross-site requests; state-changing endpoints depend entirely on CSRF tokens",
                ))
        return findings
