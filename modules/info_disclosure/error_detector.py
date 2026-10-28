import re
from typing import List
from core.models import HttpRecord, Finding

TEXT_TYPES = ("html", "json", "xml", "text", "javascript")
MAX_BODY = 1_000_000

PATTERNS = [
    ("Django debug page", "high", re.compile(r"You're seeing this error because you have <code>DEBUG = True|Django Version:")),
    ("Werkzeug debugger", "high", re.compile(r"Werkzeug Debugger|The debugger caught an exception")),
    ("Laravel/Symfony debug page", "high", re.compile(r"Whoops! There was an error|Illuminate\\\\|Symfony\\\\Component|Ignition")),
    ("Java stack trace", "medium", re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)")),
    ("Java exception class", "medium", re.compile(r"\b(?:java|javax|org\.springframework|org\.hibernate)\.[\w.]+(?:Exception|Error)\b")),
    ("Python traceback", "medium", re.compile(r"Traceback \(most recent call last\)")),
    ("PHP error message", "medium", re.compile(r"(?:Fatal error|Warning|Notice|Parse error|Uncaught \w*Exception): .{0,200}?(?: in |\()\s*/?[\w/.\-\\]+\.php(?: on line |:)\d+")),
    ("ASP.NET error page", "medium", re.compile(r"Server Error in '[^']*' Application|Stack Trace:\s*<|System\.\w+Exception")),
    ("Node.js stack trace", "medium", re.compile(r"\bat [\w.<>$ ]+ \((?:/|[A-Za-z]:\\)[^)\n]+:\d+:\d+\)")),
    ("Ruby on Rails error", "medium", re.compile(r"ActionController::\w+Error|ActiveRecord::\w+|app/controllers/\w+\.rb:\d+")),
    ("Spring Whitelabel error page", "low", re.compile(r"Whitelabel Error Page")),
    ("SQL error message", "medium", re.compile(
        r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[\w+\]|pg_query\(\)|"
        r"Unclosed quotation mark after the character string|SQLite3?::|psycopg2\.\w+Error|"
        r"mysqli?_\w+\(\)|com\.mysql\.jdbc|org\.postgresql\.util")),
    ("Server file path", "low", re.compile(r"(?:/var/www|/usr/local/\w+|/home/\w+|/opt/\w+|C:\\(?:inetpub|Users|Windows)\\)[\w/.\\\-]{3,}")),
]


class InfoDisclosureErrorDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        resp = record.response
        body = resp.body or ""
        ctype = (resp.content_type or "").lower()
        if not body or len(body) > MAX_BODY or not any(t in ctype for t in TEXT_TYPES):
            return []

        findings = []
        for kind, severity, rx in PATTERNS:
            m = rx.search(body)
            if not m:
                continue
            findings.append(Finding(
                module="info_disclosure",
                severity=severity,
                title=f"Information Disclosure: {kind}",
                location=record.request.url,
                evidence=f"{kind} found in response body (status {resp.status})",
                vector_hint="Verbose errors reveal framework, file paths and internals — use them to fingerprint the stack and craft targeted attacks",
            ))
        return findings
