import re
from typing import List
from core.models import HttpRecord, Finding

TRAVERSAL_PATTERNS = [
    (re.compile(r'\.\./'), "Unix traversal ../"),
    (re.compile(r'\.\.\\'), "Windows traversal ..\\"),
    (re.compile(r'%2e%2e%2f', re.IGNORECASE), "URL-encoded traversal %2e%2e%2f"),
    (re.compile(r'%2e%2e/', re.IGNORECASE), "Partial encoded %2e%2e/"),
    (re.compile(r'\.\.%2f', re.IGNORECASE), "Mixed encoded ..%2f"),
    (re.compile(r'%252e%252e', re.IGNORECASE), "Double-encoded %252e%252e"),
    (re.compile(r'\.\.%5c', re.IGNORECASE), "Encoded backslash ..%5c"),
    (re.compile(r'%c0%af', re.IGNORECASE), "Unicode overlong /"),
    (re.compile(r'\.\.;/'), "Tomcat bypass ..;/"),
]

SENSITIVE_FILE_HINTS = [
    (re.compile(r'/etc/passwd', re.IGNORECASE), "Linux passwd file"),
    (re.compile(r'/etc/shadow', re.IGNORECASE), "Linux shadow file"),
    (re.compile(r'/etc/hosts', re.IGNORECASE), "Linux hosts file"),
    (re.compile(r'C:\\Windows\\win\.ini', re.IGNORECASE), "Windows win.ini"),
    (re.compile(r'C:\\boot\.ini', re.IGNORECASE), "Windows boot.ini"),
    (re.compile(r'proc/self/environ', re.IGNORECASE), "Linux /proc/self/environ"),
    (re.compile(r'wp-config\.php', re.IGNORECASE), "WordPress config"),
    (re.compile(r'\.env', re.IGNORECASE), ".env file"),
]


class LfiTraversalHintDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        url = record.request.url or ""
        body = record.request.body or ""
        combined = url + " " + body

        for pattern, label in TRAVERSAL_PATTERNS:
            if pattern.search(combined):
                findings.append(Finding(
                    module="lfi",
                    severity="high",
                    title=f"Path Traversal Sequence Detected: {label}",
                    location=url,
                    evidence=f"Traversal pattern '{label}' found in request",
                    vector_hint="Traversal sequence present — test deeper traversal or encoding bypass",
                ))

        for pattern, label in SENSITIVE_FILE_HINTS:
            if pattern.search(combined):
                findings.append(Finding(
                    module="lfi",
                    severity="critical",
                    title=f"Sensitive File Path in Request: {label}",
                    location=url,
                    evidence=f"Reference to '{label}' found in request",
                    vector_hint="Sensitive file path found — verify if accessible",
                ))

        return findings
