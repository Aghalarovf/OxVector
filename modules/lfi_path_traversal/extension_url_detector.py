import re
from urllib.parse import urlparse
from typing import List
from core.models import HttpRecord, Finding

FILE_EXTENSION = re.compile(
    r'\.(php|html?|txt|xml|json|log|conf|cfg|ini|env|bak|old|'
    r'sql|db|sqlite|zip|tar|gz|rar|7z|pdf|doc|docx|xls|xlsx|'
    r'png|jpg|jpeg|gif|svg|ico|mp4|mp3|wav|csv)(\?|$|#)',
    re.IGNORECASE,
)

SENSITIVE_EXTENSIONS = {
    "php", "log", "conf", "cfg", "ini", "env", "bak", "old",
    "sql", "db", "sqlite", "zip", "tar", "gz", "rar", "7z",
}


class LfiExtensionUrlDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        url = record.request.url or ""
        parsed = urlparse(url)
        path = parsed.path

        match = FILE_EXTENSION.search(path + "?")
        if match:
            ext = match.group(1).lower()
            severity = "high" if ext in SENSITIVE_EXTENSIONS else "low"
            findings.append(Finding(
                module="lfi",
                severity=severity,
                title=f"File Extension in URL Path: .{ext}",
                location=url,
                evidence=f"URL path contains .{ext} extension: {path}",
                vector_hint=f"Check if path parameter is user-controlled — test LFI/path traversal on .{ext} serving endpoint",
            ))

        return findings