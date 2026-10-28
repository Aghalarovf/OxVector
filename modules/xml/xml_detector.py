import re
from typing import List
from core.models import HttpRecord, Finding
from modules.xml.xml_extractor import request_xml_extra

XML_DECL    = re.compile(r'<\?xml', re.IGNORECASE)
DOCTYPE     = re.compile(r'<!DOCTYPE', re.IGNORECASE)
ENTITY      = re.compile(r'<!ENTITY', re.IGNORECASE)
XML_TAG     = re.compile(r'<[a-zA-Z][\w:.-]*(\s[^>]*)?>.*?</[a-zA-Z][\w:.-]*>', re.DOTALL)


class XmlDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        body = record.request.body or ""

        if not body:
            return findings

        xml_extra = request_xml_extra(body)

        if XML_DECL.search(body):
            findings.append(Finding(
                module="xml",
                severity="medium",
                title="XML Declaration in Request Body",
                location=record.request.url,
                evidence="<?xml declaration found in request body",
                vector_hint="Inject XXE payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                extra=dict(xml_extra),
            ))

        if DOCTYPE.search(body):
            findings.append(Finding(
                module="xml",
                severity="high",
                title="DOCTYPE Declaration in Request Body",
                location=record.request.url,
                evidence="<!DOCTYPE found in request body",
                vector_hint="DOCTYPE present — test for external entity injection",
                extra=dict(xml_extra),
            ))

        if ENTITY.search(body):
            findings.append(Finding(
                module="xml",
                severity="high",
                title="ENTITY Declaration in Request Body",
                location=record.request.url,
                evidence="<!ENTITY found in request body — may already be using entities",
                vector_hint="Test with external SYSTEM entity pointing to internal resource",
                extra=dict(xml_extra),
            ))

        if not findings and XML_TAG.search(body):
            findings.append(Finding(
                module="xml",
                severity="medium",
                title="XML Structure Detected in Request Body",
                location=record.request.url,
                evidence="XML-like tags found in request body",
                vector_hint="Try injecting XML declaration and DOCTYPE to test XXE",
                extra=dict(xml_extra),
            ))

        return findings