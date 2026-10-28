import re
from typing import Optional

XML_START = re.compile(r'<\?xml|<!DOCTYPE|<[a-zA-Z][\w:.-]*[\s>/]', re.IGNORECASE)


def extract_xml(body: Optional[str]) -> Optional[str]:
    if not body:
        return None
    match = XML_START.search(body)
    if not match:
        return None
    end = body.rfind(">")
    if end < match.start():
        return None
    xml = body[match.start():end + 1].strip()
    return xml or None


def request_xml_extra(body: Optional[str]) -> dict:
    xml = extract_xml(body)
    if not xml:
        return {}
    return {"xml": xml, "xml_source": "request body"}