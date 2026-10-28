import re
from typing import List
from core.models import HttpRecord, Finding

FILENAME_ATTR = re.compile(r'filename=["\']?([^"\';\r\n]+)', re.IGNORECASE)

DANGEROUS_EXTENSIONS = {
    ".php": "critical", ".php3": "critical", ".php4": "critical",
    ".php5": "critical", ".phtml": "critical", ".phar": "critical",
    ".jsp": "critical", ".jspx": "critical",
    ".aspx": "critical", ".asp": "critical", ".cer": "critical",
    ".shtml": "high",
    ".svg": "high",
    ".html": "high", ".htm": "high",
    ".xml": "medium",
    ".js": "medium",
    ".py": "high", ".rb": "high", ".pl": "high", ".sh": "high",
    ".exe": "high", ".dll": "high", ".bat": "high", ".cmd": "high",
}


class FileUploadExtensionDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        body = record.request.body or ""

        for match in FILENAME_ATTR.finditer(body):
            filename = match.group(1).strip()
            for ext, severity in DANGEROUS_EXTENSIONS.items():
                if filename.lower().endswith(ext):
                    findings.append(Finding(
                        module="file_upload",
                        severity=severity,
                        title=f"Dangerous File Extension Uploaded: {ext}",
                        location=record.request.url,
                        evidence=f"filename='{filename}' — extension '{ext}' is executable/dangerous",
                        vector_hint=f"Server may execute '{ext}' files — verify upload directory and web-accessible path",
                    ))

        return findings
