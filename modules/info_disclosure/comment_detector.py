import re
from typing import List
from core.models import HttpRecord, Finding

COMMENT_RE = re.compile(r"<!--(?!\[if|<!\[endif)(.*?)-->", re.DOTALL)
KEYWORD_RE = re.compile(
    r"password|passwd|secret|api[_-]?key|token|credential|todo|fixme|hack|debug|"
    r"backdoor|username|test account|internal|\badmin\b|"
    r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
    re.IGNORECASE,
)


class InfoDisclosureCommentDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        resp = record.response
        body = resp.body or ""
        if "html" not in (resp.content_type or "").lower() or "<!--" not in body:
            return []

        findings = []
        for m in COMMENT_RE.finditer(body):
            text = " ".join(m.group(1).split())
            if not text or len(text) > 600:
                continue
            kw = KEYWORD_RE.search(text)
            if not kw:
                continue
            findings.append(Finding(
                module="info_disclosure",
                severity="low",
                title="Information Disclosure: Sensitive HTML Comment",
                location=record.request.url,
                evidence=f"HTML comment mentions '{kw.group(0)}': {text[:70]}",
                vector_hint="Developer comments can reveal credentials, internal hosts, hidden features and unfinished code",
            ))
            if len(findings) >= 3:
                break
        return findings