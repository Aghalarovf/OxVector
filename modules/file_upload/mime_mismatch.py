import re
from typing import List
from core.models import HttpRecord, Finding

FILENAME_ATTR  = re.compile(r'filename=["\']?([^"\';\r\n]+)', re.IGNORECASE)
PART_CT        = re.compile(r'Content-Type:\s*([^\r\n]+)', re.IGNORECASE)

IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"}
EXEC_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".jsp", ".jspx", ".asp", ".aspx", ".py", ".rb", ".pl",
    ".sh", ".exe", ".bat", ".cmd", ".html", ".htm", ".svg", ".xml", ".js",
}


class FileUploadMimeMismatch:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        body = record.request.body or ""
        req_ct = record.request.content_type or ""

        if "multipart/form-data" not in req_ct:
            return findings

        filename_match = FILENAME_ATTR.search(body)
        part_ct_match = PART_CT.search(body)

        if not filename_match:
            return findings

        filename = filename_match.group(1).strip().lower()
        declared_ct = part_ct_match.group(1).strip().lower() if part_ct_match else ""

        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1]

        if declared_ct in IMAGE_TYPES and ext in EXEC_EXTENSIONS:
            findings.append(Finding(
                module="file_upload",
                severity="critical",
                title="MIME Type / Extension Mismatch",
                location=record.request.url,
                evidence=f"Content-Type: '{declared_ct}' but filename='{filename}' — executable extension disguised as image",
                vector_hint="Server validates MIME but not extension — file may be stored and executed as script",
            ))
        elif not declared_ct and ext in EXEC_EXTENSIONS:
            findings.append(Finding(
                module="file_upload",
                severity="high",
                title=f"Executable Extension Without Content-Type: {ext}",
                location=record.request.url,
                evidence=f"filename='{filename}' with no Content-Type in part",
                vector_hint="No MIME validation — server relies on extension only",
            ))

        if "../" in filename or "..\\" in filename:
            findings.append(Finding(
                module="file_upload",
                severity="critical",
                title="Path Traversal in Upload Filename",
                location=record.request.url,
                evidence=f"filename='{filename}' contains directory traversal sequence",
                vector_hint="Upload may land outside intended directory — test writing to web root",
            ))

        return findings
