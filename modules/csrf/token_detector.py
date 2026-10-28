from typing import List
from core.models import HttpRecord, Finding
from modules.csrf.common import (
    STATE_CHANGING_METHODS,
    has_token_name,
    is_static,
    url_path,
)

SKIP_PATH_HINTS = ("login", "logout", "signin", "signout", "register", "signup", "oauth", "token")
FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")


class CsrfTokenDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        req = record.request
        method = (req.method or "").upper()
        if method not in STATE_CHANGING_METHODS or is_static(req.url):
            return []

        headers = req.headers or {}
        if not headers.get("cookie"):
            return []
        if headers.get("authorization"):
            return []

        path = url_path(req.url).lower()
        if any(h in path for h in SKIP_PATH_HINTS):
            return []

        for name in headers:
            if has_token_name(name) or name == "x-requested-with":
                return []

        for name in (req.params or {}):
            if has_token_name(str(name)):
                return []

        body = req.body or ""
        if body and has_token_name(body[:4096]):
            return []

        ctype = (req.content_type or "").lower()
        if "json" in ctype:
            severity = "low"
            note = "JSON body with cookie auth and no CSRF token or custom header"
            hint = "Check whether the endpoint also accepts form or text/plain bodies, or has permissive CORS — if so, forge a cross-site request"
        elif not ctype or any(t in ctype for t in FORM_TYPES):
            severity = "medium"
            note = "State-changing request with cookie auth and no CSRF token"
            hint = "Build an auto-submitting cross-site form for this request and check whether the action succeeds"
        else:
            severity = "low"
            note = f"State-changing request ({ctype}) with cookie auth and no CSRF token"
            hint = "Test whether the server accepts the request with a simple content type from a cross-site form"

        return [Finding(
            module="csrf",
            severity=severity,
            title="CSRF: State-Changing Request Without Anti-CSRF Token",
            location=req.url,
            evidence=f"{method} {url_path(req.url)} — {note}",
            vector_hint=hint,
        )]
