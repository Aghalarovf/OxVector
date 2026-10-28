import re
from typing import List
from core.models import HttpRecord, Finding

TEXT_TYPES = ("html", "json", "xml", "text", "javascript", "ecmascript")
MAX_BODY = 2_000_000
PLACEHOLDER_WORDS = (
    "your", "example", "xxx", "changeme", "placeholder", "password", "secret",
    "token", "<", ">", "{{", "${", "****", "null", "undefined", "dummy", "sample",
)

SECRET_PATTERNS = [
    ("Private key block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("AWS access key ID", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe live secret key", "critical", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")),
    ("Slack token", "high", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("SendGrid API key", "high", re.compile(r"\bSG\.[\w\-]{16,}\.[\w\-]{16,}\b")),
    ("Google API key", "medium", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Twilio API key", "medium", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Mailgun API key", "medium", re.compile(r"\bkey-[0-9a-f]{32}\b")),
]
GENERIC_RE = re.compile(
    r"""["']?(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{8,})["']""",
    re.IGNORECASE,
)
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


def _redact(value: str) -> str:
    return f"{value[:4]}... ({len(value)} chars)"


class InfoDisclosureSecretDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        resp = record.response
        body = resp.body or ""
        ctype = (resp.content_type or "").lower()
        if not body or len(body) > MAX_BODY or not any(t in ctype for t in TEXT_TYPES):
            return []

        findings = []
        url = record.request.url

        for kind, severity, rx in SECRET_PATTERNS:
            m = rx.search(body)
            if not m or "EXAMPLE" in m.group(0):
                continue
            findings.append(Finding(
                module="info_disclosure",
                severity=severity,
                title=f"Information Disclosure: {kind} in Response",
                location=url,
                evidence=f"{kind} exposed: {_redact(m.group(0))}",
                vector_hint="Credentials in client-visible content must be treated as compromised — rotate and verify what they grant",
            ))

        for m in GENERIC_RE.finditer(body):
            value = m.group(1)
            lowered = value.lower()
            if any(w in lowered for w in PLACEHOLDER_WORDS):
                continue
            findings.append(Finding(
                module="info_disclosure",
                severity="medium",
                title="Information Disclosure: Hardcoded Secret-Like Value",
                location=url,
                evidence=f"Secret-like assignment in response: {_redact(value)}",
                vector_hint="Hardcoded credential-style values in client content — verify whether they are live",
            ))
            break

        m = PRIVATE_IP_RE.search(body)
        if m:
            findings.append(Finding(
                module="info_disclosure",
                severity="low",
                title="Information Disclosure: Internal IP in Response Body",
                location=url,
                evidence=f"Private address {m.group(0)} found in response body",
                vector_hint="Internal addresses reveal network layout and may point to SSRF-reachable hosts or backends",
            ))
        return findings
