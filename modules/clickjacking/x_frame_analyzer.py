import re
from typing import List
from core.models import HttpRecord, Finding
from core.http_utils import url_path
from modules.clickjacking.common import (
    FRAMEBUST_RE,
    SENSITIVE_PATH_RE,
    is_html_document,
    parse_frame_ancestors,
)

VALID_XFO = ("deny", "sameorigin")
META_XFO_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?x-frame-options""",
    re.IGNORECASE,
)


class ClickjackingXFrameAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        if not is_html_document(record):
            return []

        headers = record.response.headers or {}
        url = record.request.url
        xfo = (headers.get("x-frame-options") or "").strip()
        ancestors = parse_frame_ancestors(headers.get("content-security-policy", ""))
        body = record.response.body or ""
        req_headers = record.request.headers or {}

        findings = []

        if not xfo and ancestors is None:
            sensitive = bool(
                req_headers.get("cookie")
                or SENSITIVE_PATH_RE.search(url_path(url))
                or re.search(r"type\s*=\s*[\"']?password", body, re.IGNORECASE)
            )
            severity = "medium" if sensitive else "low"
            findings.append(Finding(
                module="clickjacking",
                severity=severity,
                title="Clickjacking: No Frame Protection",
                location=url,
                evidence="HTML response has neither X-Frame-Options nor CSP frame-ancestors",
                vector_hint="Embed the page in an <iframe> on an attacker-controlled page and overlay a decoy UI over sensitive actions",
                extra={
                    "issue": "missing",
                    "headers": ["X-Frame-Options", "Content-Security-Policy: frame-ancestors"],
                    "reason": "Missing: X-Frame-Options header and CSP frame-ancestors directive (nothing prevents framing)",
                },
            ))

            if body and FRAMEBUST_RE.search(body):
                findings.append(Finding(
                    module="clickjacking",
                    severity="low",
                    title="Clickjacking: Reliance on JavaScript Frame Busting",
                    location=url,
                    evidence="Frame-busting script found with no X-Frame-Options or CSP frame-ancestors",
                    vector_hint="JavaScript framebusters can be bypassed with iframe sandbox or double framing; use header-based protection",
                    extra={
                        "issue": "weak",
                        "headers": ["X-Frame-Options", "Content-Security-Policy: frame-ancestors"],
                        "reason": "Weak: only a JavaScript frame-busting script is used; X-Frame-Options and CSP frame-ancestors are missing",
                    },
                ))

            if body and META_XFO_RE.search(body):
                findings.append(Finding(
                    module="clickjacking",
                    severity="low",
                    title="Clickjacking: X-Frame-Options Set via Meta Tag",
                    location=url,
                    evidence="X-Frame-Options declared in <meta http-equiv> — ignored by browsers",
                    vector_hint="Frame protection must be delivered as an HTTP response header, not a meta tag",
                    extra={
                        "issue": "weak",
                        "headers": ["X-Frame-Options"],
                        "reason": "Weak: X-Frame-Options is set in a <meta> tag, which browsers ignore; the real HTTP header is missing",
                    },
                ))

            return findings

        if xfo:
            value = xfo.lower()
            if value.startswith("allow-from"):
                findings.append(Finding(
                    module="clickjacking",
                    severity="low",
                    title="Clickjacking: Obsolete X-Frame-Options ALLOW-FROM",
                    location=url,
                    evidence=f"X-Frame-Options: {xfo}",
                    vector_hint="ALLOW-FROM is ignored by modern browsers, leaving the page frameable; use CSP frame-ancestors instead",
                    extra={
                        "issue": "weak",
                        "headers": ["X-Frame-Options"],
                        "reason": f"Weak: X-Frame-Options value '{xfo}' uses obsolete ALLOW-FROM, ignored by modern browsers",
                    },
                ))
            elif value not in VALID_XFO:
                severity = "medium" if ancestors is None else "low"
                findings.append(Finding(
                    module="clickjacking",
                    severity=severity,
                    title="Clickjacking: Invalid X-Frame-Options Value",
                    location=url,
                    evidence=f"X-Frame-Options: {xfo}",
                    vector_hint="Browsers ignore invalid or multi-value X-Frame-Options, so the page can be framed unless CSP frame-ancestors also protects it",
                    extra={
                        "issue": "weak",
                        "headers": ["X-Frame-Options"],
                        "reason": f"Weak: X-Frame-Options value '{xfo}' is invalid (only DENY or SAMEORIGIN are valid)"
                                  + ("" if ancestors is None else "; CSP frame-ancestors is present"),
                    },
                ))

        return findings