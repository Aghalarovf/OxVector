import re

SENSITIVE_PATH_RE = re.compile(
    r"login|signin|account|profile|settings|admin|payment|checkout|transfer|"
    r"dashboard|password|billing|wallet|order|delete|security",
    re.IGNORECASE,
)

FRAMEBUST_RE = re.compile(
    r"top\.location|self\s*!==?\s*top|top\s*!==?\s*self|window\.top|parent\.location",
    re.IGNORECASE,
)

NON_DOCUMENT_DESTS = (
    "empty", "script", "style", "image", "font", "audio", "video",
    "worker", "serviceworker", "manifest", "object", "embed",
)


def is_html_document(record) -> bool:
    req = record.request
    resp = record.response
    if (req.method or "").upper() != "GET":
        return False
    if resp.status != 200:
        return False
    if "html" not in (resp.content_type or "").lower():
        return False
    headers = req.headers or {}
    if (headers.get("x-requested-with") or "").lower() == "xmlhttprequest":
        return False
    if (headers.get("sec-fetch-dest") or "").lower() in NON_DOCUMENT_DESTS:
        return False
    return True


def parse_frame_ancestors(csp: str):
    if not csp:
        return None
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if parts and parts[0].lower() == "frame-ancestors":
            return [p for p in parts[1:]]
    return None
