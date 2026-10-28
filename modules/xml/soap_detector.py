import re
from typing import List
from core.models import HttpRecord, Finding
from modules.xml.xml_extractor import request_xml_extra

SOAP_PATTERNS = [
    (re.compile(r'<soap:', re.IGNORECASE), "SOAP Envelope"),
    (re.compile(r'<SOAP-ENV:', re.IGNORECASE), "SOAP-ENV Envelope"),
    (re.compile(r'<wsdl:', re.IGNORECASE), "WSDL structure"),
    (re.compile(r'xmlns:soap\s*=', re.IGNORECASE), "SOAP namespace"),
    (re.compile(r'soapAction', re.IGNORECASE), "SOAPAction header"),
    (re.compile(r'\.asmx', re.IGNORECASE), "ASP.NET ASMX web service"),
    (re.compile(r'\.wsdl', re.IGNORECASE), "WSDL endpoint"),
]


class XmlSoapDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        body = record.request.body or ""
        url = record.request.url or ""
        headers = record.request.headers or {}
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        combined = body + url + header_str
        xml_extra = request_xml_extra(body)

        for pattern, label in SOAP_PATTERNS:
            if pattern.search(combined):
                findings.append(Finding(
                    module="xml",
                    severity="high",
                    title=f"SOAP/WSDL Endpoint Detected: {label}",
                    location=record.request.url,
                    evidence=f"{label} pattern found",
                    vector_hint="SOAP endpoints are prime XXE targets — inject entity in SOAP body",
                    extra=dict(xml_extra),
                ))

        return findings