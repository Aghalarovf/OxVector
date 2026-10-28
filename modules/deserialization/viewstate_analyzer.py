import re
from typing import List
from core.models import HttpRecord, Finding
from modules.deserialization.common import preview
from modules.deserialization import signatures

VIEWSTATE_INPUT_RE = re.compile(
    r"""<input[^>]*name\s*=\s*["']__VIEWSTATE["'][^>]*value\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)
VIEWSTATE_INPUT_ALT_RE = re.compile(
    r"""<input[^>]*value\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']__VIEWSTATE["']""",
    re.IGNORECASE,
)


class DeserializationViewStateAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        body = record.response.body or ""
        values = []

        for name, value in (req.params or {}).items():
            if str(name).upper() == "__VIEWSTATE" and isinstance(value, str):
                values.append(("request parameter", value))

        if body and "__VIEWSTATE" in body:
            for rx in (VIEWSTATE_INPUT_RE, VIEWSTATE_INPUT_ALT_RE):
                m = rx.search(body)
                if m:
                    values.append(("response form field", m.group(1)))
                    break

        marked = set()
        for where, value in values:
            if not value:
                continue
            signature = signatures.viewstate()
            if signature and where not in marked:
                marked.add(where)
                findings.append(signatures.language_finding(signature, req.url, f"__VIEWSTATE in {where}"))
            if value.startswith("/wE"):
                findings.append(Finding(
                    module="deserialization",
                    severity="medium",
                    title="Deserialization: ASP.NET ViewState Without Encryption",
                    location=req.url,
                    evidence=f"__VIEWSTATE in {where} uses the plain LosFormatter prefix ({preview(value, 12)})",
                    vector_hint="Unencrypted ViewState exposes state to the client; if the MAC key is weak or leaked it can be forged for deserialization",
                ))
            else:
                findings.append(Finding(
                    module="deserialization",
                    severity="low",
                    title="Deserialization: ASP.NET ViewState Present",
                    location=req.url,
                    evidence=f"__VIEWSTATE in {where} (prefix {preview(value, 12)})",
                    vector_hint="Check whether ViewState MAC and encryption are enforced and the machineKey is not a known default",
                ))

        gen = False
        for name in (req.params or {}):
            if str(name).upper() == "__VIEWSTATEGENERATOR":
                gen = True
        if values and not gen and "__VIEWSTATEGENERATOR" not in body:
            findings.append(Finding(
                module="deserialization",
                severity="info",
                title="Deserialization: ViewState Without Generator Field",
                location=req.url,
                evidence="__VIEWSTATE present without __VIEWSTATEGENERATOR",
                vector_hint="Unusual ViewState layout — possibly legacy ASP.NET (<4.5) or a custom setup",
            ))
        return findings