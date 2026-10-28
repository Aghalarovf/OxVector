import html
import re
from typing import List, Optional
from urllib.parse import unquote
from core.models import HttpRecord, Finding
from core.http_utils import SESSION_COOKIE_RE, parse_cookie_header, is_static

MIN_VALUE_LENGTH = 6
MAX_VALUE_LENGTH = 2000
DANGEROUS_CHARS = set("<>\"'`")
TEXTUAL_TYPES = ("text/", "json", "xml", "javascript", "html")
SKIPPED_HEADERS = {"set-cookie", "date", "content-length", "content-type", "server"}


def _context(body: str, index: int) -> str:
    before = body[max(0, index - 400):index]
    lowered = before.lower()
    last_script_open = lowered.rfind("<script")
    last_script_close = lowered.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "inside a script block"
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open != -1 and last_comment_open > last_comment_close:
        return "inside an HTML comment"
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        quote_double = before[last_lt:].count('"') % 2 == 1
        quote_single = before[last_lt:].count("'") % 2 == 1
        if quote_double or quote_single:
            return "inside a quoted HTML attribute"
        return "inside an HTML tag"
    return "inside HTML text"


def _find_reflection(body: str, value: str) -> Optional[tuple]:
    variants = [(value, "raw")]
    decoded = unquote(value)
    if decoded != value:
        variants.append((decoded, "url-decoded"))
    escaped = html.escape(decoded, quote=True)
    if escaped != decoded:
        variants.append((escaped, "html-escaped"))
    for candidate, form in variants:
        if len(candidate) < MIN_VALUE_LENGTH:
            continue
        index = body.find(candidate)
        if index != -1:
            return candidate, form, index
    return None


class CookieSecurityInjectionAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        resp = record.response
        url = req.url

        if is_static(url):
            return findings

        cookies = parse_cookie_header((req.headers or {}).get("cookie", ""))
        if not cookies:
            return findings

        content_type = (resp.content_type or (resp.headers or {}).get("content-type", "") or "").lower()
        body = resp.body if isinstance(resp.body, str) else ""
        body_checkable = bool(body) and (not content_type or any(t in content_type for t in TEXTUAL_TYPES))

        for name, value in cookies.items():
            if len(value) < MIN_VALUE_LENGTH or len(value) > MAX_VALUE_LENGTH:
                continue

            if body_checkable:
                hit = _find_reflection(body, value)
                if hit:
                    candidate, form, index = hit
                    contains_dangerous = any(c in DANGEROUS_CHARS for c in unquote(value))
                    context = _context(body, index)
                    session_like = bool(SESSION_COOKIE_RE.search(name))
                    if form != "html-escaped" and contains_dangerous:
                        severity = "high"
                        title = "Cookie Value Reflected Without Encoding"
                        hint = "Cookie is attacker-controllable through cookie injection or a sibling subdomain; reflected markup characters indicate possible XSS"
                    elif form == "html-escaped":
                        severity = "low"
                        title = "Cookie Value Reflected In Response (Encoded)"
                        hint = "Value is HTML-escaped on output; verify encoding holds in script and attribute contexts"
                    elif session_like:
                        severity = "medium"
                        title = "Session Cookie Value Reflected In Response Body"
                        hint = "Reflected session identifiers are exposed to XSS, caches and logs, and defeat the purpose of HttpOnly"
                    else:
                        severity = "low"
                        title = "Cookie Value Reflected In Response"
                        hint = "Test with markup, quote and newline characters in the cookie value to confirm injection"
                    findings.append(Finding(
                        module="cookie_security",
                        severity=severity,
                        title=f"Cookie Security: {title}",
                        location=url,
                        evidence=f"Cookie {name} value reflected in response body ({form}), {context}",
                        vector_hint=hint,
                        confidence="candidate",
                        extra={"cookie": name, "context": context, "form": form},
                    ))

            for header_name, header_value in (resp.headers or {}).items():
                if header_name.lower() in SKIPPED_HEADERS or not isinstance(header_value, str):
                    continue
                if value in header_value or (unquote(value) != value and unquote(value) in header_value):
                    findings.append(Finding(
                        module="cookie_security",
                        severity="medium",
                        title="Cookie Security: Cookie Value Reflected In Response Header",
                        location=url,
                        evidence=f"Cookie {name} value reflected in response header {header_name}",
                        vector_hint="Test CRLF sequences in the cookie value for response header injection or response splitting",
                        confidence="candidate",
                        extra={"cookie": name, "header": header_name},
                    ))
                    break
        return findings