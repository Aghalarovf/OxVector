import re
from typing import List
from core.models import HttpRecord, Finding
from core.http_utils import SESSION_COOKIE_RE, parse_cookie_header, parse_set_cookies, url_path

LOGIN_PATH_RE = re.compile(r"login|signin|sign-in|authenticate|session|sso/callback", re.IGNORECASE)
SUCCESS_REDIRECTS = (301, 302, 303, 307, 308)


class CookieSecuritySessionFixationAnalyzer:
    def analyze_all(self, records: List[HttpRecord]) -> List[Finding]:
        findings = []
        for record in records:
            req = record.request
            resp = record.response
            if (req.method or "").upper() != "POST":
                continue
            if not LOGIN_PATH_RE.search(url_path(req.url)):
                continue
            if resp.status not in SUCCESS_REDIRECTS and not (
                resp.status == 200 and "token" in (resp.body or "")[:2000].lower()
            ):
                continue

            sent = {
                n: v for n, v in parse_cookie_header((req.headers or {}).get("cookie", "")).items()
                if SESSION_COOKIE_RE.search(n)
            }
            if not sent:
                continue

            rotated = {
                c["name"]: c["value"]
                for c in parse_set_cookies((resp.headers or {}).get("set-cookie", ""))
            }
            for name, value in sent.items():
                if name in rotated and rotated[name] == value:
                    state = "re-issued unchanged"
                elif name not in rotated:
                    state = "not replaced"
                else:
                    continue
                findings.append(Finding(
                    module="cookie_security",
                    severity="medium",
                    title="Cookie Security: Session ID Not Rotated After Login",
                    location=req.url,
                    evidence=f"{name} sent with login request and {state} in the successful response",
                    vector_hint="Candidate session fixation: obtain a pre-login session ID, make the victim authenticate with it, then reuse it",
                    confidence="candidate",
                ))
        return findings
