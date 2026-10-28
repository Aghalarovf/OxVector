import re
from typing import List
from core.models import HttpRecord, Finding

FILE_SERVING_PATTERNS = [
    (re.compile(r'/image\?.*?(img|src|file|path|name)=', re.IGNORECASE), "Image serving endpoint"),
    (re.compile(r'/download\?.*?(file|path|doc|name|resource)=', re.IGNORECASE), "Download endpoint"),
    (re.compile(r'/view\?.*?(file|path|page|doc|name)=', re.IGNORECASE), "View endpoint"),
    (re.compile(r'/static\?.*?(file|path|name|resource)=', re.IGNORECASE), "Static file endpoint"),
    (re.compile(r'/assets\?.*?(file|path|name)=', re.IGNORECASE), "Assets endpoint"),
    (re.compile(r'/media\?.*?(file|path|src|name)=', re.IGNORECASE), "Media endpoint"),
    (re.compile(r'/load\?.*?(file|path|template|module)=', re.IGNORECASE), "Load endpoint"),
    (re.compile(r'/include\?.*?(file|path|page|module)=', re.IGNORECASE), "Include endpoint"),
    (re.compile(r'/render\?.*?(file|template|page)=', re.IGNORECASE), "Render endpoint"),
    (re.compile(r'/read\?.*?(file|path|doc)=', re.IGNORECASE), "Read endpoint"),
    (re.compile(r'/open\?.*?(file|path|doc)=', re.IGNORECASE), "Open endpoint"),
    (re.compile(r'/export\?.*?(file|path|format|template)=', re.IGNORECASE), "Export endpoint"),
    (re.compile(r'/(images|img|files|uploads|docs|documents)/.*\.(png|jpg|jpeg|gif|pdf|txt|xml)', re.IGNORECASE), "Direct file path in URL"),
]


class LfiPatternUrlDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        url = record.request.url or ""

        for pattern, label in FILE_SERVING_PATTERNS:
            if pattern.search(url):
                findings.append(Finding(
                    module="lfi",
                    severity="high",
                    title=f"File Serving Pattern Detected: {label}",
                    location=url,
                    evidence=f"{label} URL pattern: {url[:120]}",
                    vector_hint="Replace file parameter value with ../../../etc/passwd or php://filter payload",
                ))

        return findings
