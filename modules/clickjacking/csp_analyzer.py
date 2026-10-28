import re
from typing import List
from urllib.parse import urlparse
from core.models import HttpRecord, Finding
from modules.clickjacking.common import is_html_document, parse_frame_ancestors

WILDCARD_SUBDOMAIN_RE = re.compile(r"^https?://\*\.", re.IGNORECASE)
PERMISSIVE_SOURCES = ("*", "http:", "https:", "data:")


def _strip_wildcard_prefix(source: str) -> str:
    return re.sub(r"^https?://\*\.", "", source, flags=re.IGNORECASE)


def _host_of(source: str) -> str:
    try:
        return (urlparse(source).hostname or "").lower()
    except Exception:
        return ""


class ClickjackingCspAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        if not is_html_document(record):
            return []

        headers = record.response.headers or {}
        url = record.request.url
        csp = headers.get("content-security-policy", "")
        findings = []

        if not csp:
            findings.append(Finding(
                module="clickjacking",
                severity="low",
                title="Clickjacking: No Content-Security-Policy Header",
                location=url,
                evidence="Response has no Content-Security-Policy header",
                vector_hint="Without a frame-ancestors directive the page relies entirely on X-Frame-Options, if any, to prevent framing",
                extra={
                    "issue": "missing",
                    "headers": ["Content-Security-Policy"],
                    "reason": "Missing: Content-Security-Policy header, so there is no frame-ancestors directive (only X-Frame-Options, if any, protects the page)",
                },
            ))
            return findings

        ancestors = parse_frame_ancestors(csp)

        if ancestors is None:
            findings.append(Finding(
                module="clickjacking",
                severity="low",
                title="Clickjacking: CSP Present Without frame-ancestors Directive",
                location=url,
                evidence=f"Content-Security-Policy: {csp}",
                vector_hint="A CSP without frame-ancestors does not restrict framing; the page relies on X-Frame-Options, if any",
                extra={
                    "issue": "missing",
                    "headers": ["Content-Security-Policy: frame-ancestors"],
                    "reason": "Missing: frame-ancestors directive in the Content-Security-Policy header (the CSP does not restrict framing)",
                },
            ))
            return findings

        lowered = [a.lower() for a in ancestors]

        if lowered == ["'none'"]:
            return findings

        permissive = [a for a in ancestors if a.lower() in PERMISSIVE_SOURCES]
        if permissive:
            findings.append(Finding(
                module="clickjacking",
                severity="high",
                title="Clickjacking: Permissive CSP frame-ancestors",
                location=url,
                evidence=f"frame-ancestors {' '.join(ancestors)}",
                vector_hint="A wildcard or scheme-wide source in frame-ancestors lets any site embed this page in an iframe",
                extra={
                    "issue": "weak",
                    "headers": ["Content-Security-Policy: frame-ancestors"],
                    "reason": f"Weak: frame-ancestors allows {', '.join(permissive)}, so any site can embed the page",
                },
            ))

        wildcard_entries = [a for a in ancestors if WILDCARD_SUBDOMAIN_RE.match(a)]
        if wildcard_entries:
            apex_hosts = {
                _host_of(a) for a in ancestors
                if not WILDCARD_SUBDOMAIN_RE.match(a) and not a.startswith("'")
            }
            covers_apex_too = any(
                _strip_wildcard_prefix(w).lower() in apex_hosts for w in wildcard_entries
            )
            if covers_apex_too:
                findings.append(Finding(
                    module="clickjacking",
                    severity="medium",
                    title="Clickjacking: CSP frame-ancestors Allows Apex Domain and All Subdomains",
                    location=url,
                    evidence=f"frame-ancestors {' '.join(ancestors)}",
                    vector_hint="Any current or future subdomain, including a compromised or attacker-controlled one, can embed this page",
                    extra={
                        "issue": "weak",
                        "headers": ["Content-Security-Policy: frame-ancestors"],
                        "reason": f"Weak: frame-ancestors allows the apex domain and all its subdomains ({', '.join(wildcard_entries)})",
                    },
                ))
            else:
                findings.append(Finding(
                    module="clickjacking",
                    severity="medium",
                    title="Clickjacking: Wildcard Subdomain in CSP frame-ancestors",
                    location=url,
                    evidence=f"frame-ancestors {' '.join(ancestors)}",
                    vector_hint="Any current or future subdomain, including a compromised or attacker-controlled one, can embed this page",
                    extra={
                        "issue": "weak",
                        "headers": ["Content-Security-Policy: frame-ancestors"],
                        "reason": f"Weak: frame-ancestors contains wildcard subdomain source(s): {', '.join(wildcard_entries)}",
                    },
                ))

        return findings