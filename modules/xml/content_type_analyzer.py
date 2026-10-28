from typing import List
from core.models import HttpRecord, Finding
from modules.xml.xml_extractor import request_xml_extra

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/xslt+xml",
    "application/mathml+xml",
    "application/svg+xml",
    "text/html",
]


class XmlContentTypeAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        ct = record.request.content_type or ""
        xml_extra = request_xml_extra(record.request.body)

        for xml_ct in XML_CONTENT_TYPES:
            if xml_ct in ct:
                severity = "high" if "soap" in xml_ct else "medium"
                findings.append(Finding(
                    module="xml",
                    severity=severity,
                    title=f"XML Content-Type Detected: {xml_ct}",
                    location=record.request.url,
                    evidence=f"Request Content-Type: {ct}",
                    vector_hint="Endpoint accepts XML — inject XXE payload in body",
                    extra=dict(xml_extra),
                ))
                break

        return findings