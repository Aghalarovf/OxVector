import re
from typing import List
from core.models import HttpRecord, Finding
from modules.csrf.common import has_token_name

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR_RE = r"""{name}\s*=\s*["']?([^"'\s>]+)"""
INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
META_TOKEN_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']?[^"'>]*(csrf|xsrf)[^"'>]*["']?""",
    re.IGNORECASE,
)


def _attr(attrs: str, name: str) -> str:
    m = re.search(ATTR_RE.format(name=name), attrs, re.IGNORECASE)
    return m.group(1) if m else ""


class CsrfFormAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        resp = record.response
        ctype = (resp.content_type or "").lower()
        body = resp.body or ""
        if "html" not in ctype or not body or resp.status >= 400:
            return []
        if META_TOKEN_RE.search(body):
            return []

        findings = []
        for match in FORM_RE.finditer(body):
            attrs, inner = match.group(1), match.group(2)
            method = (_attr(attrs, "method") or "get").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue

            has_token = False
            has_password = False
            for inp in INPUT_RE.finditer(inner):
                inp_attrs = inp.group(1)
                if has_token_name(_attr(inp_attrs, "name")):
                    has_token = True
                    break
                if _attr(inp_attrs, "type").lower() == "password":
                    has_password = True
            if has_token:
                continue

            action = _attr(attrs, "action") or "(self)"
            severity = "low" if has_password else "medium"
            kind = "login/credential form" if has_password else "form"
            findings.append(Finding(
                module="csrf",
                severity=severity,
                title="CSRF: HTML Form Without Anti-CSRF Token",
                location=record.request.url,
                evidence=f"{method} {kind} action={action} has no anti-CSRF token field",
                vector_hint="Build an auto-submitting cross-site form for this action and verify the server accepts it without a token",
            ))
        return findings
