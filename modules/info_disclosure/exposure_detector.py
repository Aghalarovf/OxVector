import re
from typing import List
from core.models import HttpRecord, Finding
from core.http_utils import url_path

DIR_LISTING_RE = re.compile(r"<title>Index of /|<h1>Index of /|Directory listing for /", re.IGNORECASE)

PATH_RULES = [
    (re.compile(r"/\.env(\.[\w\-]+)?$"), "Exposed .env File", "critical", None),
    (re.compile(r"/\.git(/|$)"), "Exposed .git Repository", "high", None),
    (re.compile(r"/\.svn(/|$)"), "Exposed .svn Repository", "high", None),
    (re.compile(r"/\.(htpasswd|htaccess)$"), "Exposed Apache Config File", "high", None),
    (re.compile(r"/(wp-config\.php|web\.config|config\.inc\.php)(\.\w+|~)$"), "Exposed Configuration Backup", "high", None),
    (re.compile(r"\.(sql|dump)(\.gz|\.zip)?$"), "Exposed Database Dump", "high", "non_html"),
    (re.compile(r"\.(bak|old|orig|swp|backup|save)$|~$"), "Exposed Backup or Temporary File", "medium", None),
    (re.compile(r"/\.ds_store$"), "Exposed .DS_Store File", "low", None),
    (re.compile(r"/(phpinfo|info)\.php$"), "Exposed phpinfo Page", "medium", "PHP Version"),
    (re.compile(r"/server-status/?$"), "Exposed Apache server-status", "medium", "Apache Server Status"),
    (re.compile(r"/actuator/(env|heapdump|beans|mappings|configprops|threaddump|httptrace)$"), "Sensitive Spring Actuator Endpoint", "high", None),
    (re.compile(r"/actuator/?$|/actuator/(health|info|metrics)$"), "Exposed Spring Actuator Endpoint", "low", None),
    (re.compile(r"/(swagger-ui(\.html)?|swagger\.json|swagger\.yaml|openapi\.json|openapi\.yaml|api-docs|v2/api-docs|v3/api-docs)/?$"), "Exposed API Documentation", "low", None),
    (re.compile(r"/console/?$"), "Exposed Debug Console", "high", "Werkzeug|Interactive Console"),
    (re.compile(r"/(debug|trace|heapdump|elmah\.axd|_profiler)(/|$)"), "Exposed Debug Endpoint", "medium", None),
]


class InfoDisclosureExposureDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        resp = record.response
        url = req.url
        path = url_path(url).lower()
        body = resp.body or ""
        ctype = (resp.content_type or "").lower()

        if resp.status == 200 and (req.method or "").upper() == "GET":
            for rx, title, severity, check in PATH_RULES:
                if not rx.search(path):
                    continue
                if check == "non_html" and "html" in ctype:
                    continue
                if check and check != "non_html" and not re.search(check, body):
                    continue
                findings.append(Finding(
                    module="info_disclosure",
                    severity=severity,
                    title=f"Information Disclosure: {title}",
                    location=url,
                    evidence=f"{title} reachable (status 200) at {path.rsplit('/', 1)[-1] or path}",
                    vector_hint="Download and inspect the resource; look for credentials, source code or internal configuration",
                ))
                break

            if path.endswith(".map"):
                findings.append(Finding(
                    module="info_disclosure",
                    severity="low",
                    title="Information Disclosure: Source Map Accessible",
                    location=url,
                    evidence="JavaScript source map served (status 200)",
                    vector_hint="Source maps reconstruct original source, internal paths and hidden endpoints",
                ))

        if resp.status == 200 and "html" in ctype and body and DIR_LISTING_RE.search(body[:20000]):
            findings.append(Finding(
                module="info_disclosure",
                severity="medium",
                title="Information Disclosure: Directory Listing Enabled",
                location=url,
                evidence="Response is an automatic directory index",
                vector_hint="Browse the listing for backups, configs and source files",
            ))

        if "javascript" in ctype and body and re.search(r"//[#@]\s*sourceMappingURL=", body[-2000:]):
            findings.append(Finding(
                module="info_disclosure",
                severity="info",
                title="Information Disclosure: Source Map Reference in JavaScript",
                location=url,
                evidence="sourceMappingURL comment present in script",
                vector_hint="Fetch the referenced .map file and check whether it is publicly accessible",
            ))
        return findings
