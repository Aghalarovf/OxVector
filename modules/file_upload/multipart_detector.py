import re
from typing import List
from core.models import HttpRecord, Finding

MULTIPART_CT = re.compile(r'multipart/form-data', re.IGNORECASE)
FILENAME_ATTR = re.compile(r'filename=["\']?([^"\';\r\n]+)', re.IGNORECASE)
INPUT_FILE = re.compile(r'<input[^>]*type=["\']?file["\']?[^>]*>', re.IGNORECASE)
INPUT_NAME = re.compile(r'name=["\']?([^"\'>\s]+)', re.IGNORECASE)


class FileUploadMultipartDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req_ct = record.request.content_type or ""
        body = record.request.body or ""
        resp_body = record.response.body or ""

        if MULTIPART_CT.search(req_ct):
            filename_match = FILENAME_ATTR.search(body)
            filename = filename_match.group(1).strip() if filename_match else "unknown"
            findings.append(Finding(
                module="file_upload",
                severity="medium",
                title="Multipart File Upload Request Detected",
                location=record.request.url,
                evidence=f"Content-Type: multipart/form-data — filename='{filename}'",
                vector_hint="Test malicious file upload: change filename extension, MIME type, add magic bytes",
            ))

        for match in INPUT_FILE.finditer(resp_body):
            tag = match.group(0)
            name_match = INPUT_NAME.search(tag)
            field_name = name_match.group(1) if name_match else "unknown"
            findings.append(Finding(
                module="file_upload",
                severity="medium",
                title="File Upload Input Field in HTML",
                location=record.request.url,
                evidence=f"<input type='file'> field name='{field_name}' in response",
                vector_hint=f"Upload field '{field_name}' — test with webshell, polyglot file, path traversal filename",
            ))

        return findings
