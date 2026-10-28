import re
from typing import List
from core.models import HttpRecord, Finding

FILE_PARAMS = re.compile(
    r'^(file|path|page|template|include|load|doc|src|resource|'
    r'view|dir|folder|location|module|conf|config|setting|lang|'
    r'locale|layout|skin|theme|style|url|uri|route|action)$',
    re.IGNORECASE,
)


class LfiFileParamDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        params = record.request.params or {}

        for key, value in params.items():
            if FILE_PARAMS.match(key):
                val_str = str(value)
                findings.append(Finding(
                    module="lfi",
                    severity="high",
                    title="File Path Parameter Detected",
                    location=record.request.url,
                    evidence=f"Param '{key}={val_str[:80]}' — file/path loading parameter",
                    vector_hint=f"Test '{key}' with ../../../etc/passwd or php://filter/convert.base64-encode/resource=index.php",
                ))

        return findings
