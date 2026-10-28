from typing import List
from core.models import HttpRecord, Finding
from modules.deserialization.common import (
    classify_text,
    parse_cookie_header,
    preview,
)
from modules.deserialization import decoder, signatures
from modules.csrf.common import parse_set_cookies

SERIALIZED_CONTENT_TYPES = {
    "application/x-java-serialized-object": "Java serialized object",
    "application/x-java-object": "Java serialized object",
    "application/x-python-pickle": "Python pickle",
    "application/x-php-serialized": "PHP serialized object",
}
SKIP_HEADERS = {"user-agent", "accept", "accept-language", "accept-encoding", "host", "referer", "origin", "connection"}


def _flat(params):
    for k, v in (params or {}).items():
        if isinstance(v, list):
            for item in v:
                yield str(k), item
        else:
            yield str(k), v


class DeserializationSerializedObjectDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        resp = record.response
        marked = set()

        def mark(signature, label, decoded=None):
            if not signature:
                return
            key = (signature["id"], label)
            if key in marked:
                return
            marked.add(key)
            findings.append(signatures.language_finding(signature, req.url, label, decoded=decoded))

        def add(severity, where, name, value, side, decoded):
            kind = (decoded.signature.get("kinds") or [None])[0] or decoded.language
            mark(decoded.signature, f"{side} {where} '{name}'", decoded=decoded)
            evidence = f"{where} '{name}' carries a {kind} (starts with {preview(value)})"
            if decoded.encoding_chain:
                evidence += f" [decoded via {decoded.encoding_summary}]"
            findings.append(Finding(
                module="deserialization",
                severity=severity,
                title=f"Deserialization: {kind} in {side} {where}",
                location=req.url,
                evidence=evidence,
                vector_hint="Serialized data is round-tripped through the client — test whether the server deserializes it and whether gadget chains are reachable",
                extra={"decoded_analysis": dict(decoded.analysis)} if decoded.analysis else {},
            ))

        for name, value in _flat(req.params):
            decoded = decoder.decode_candidates(value)
            if decoded and decoded.signature:
                add("high", "parameter", name, value, "Request", decoded)

        for name, value in parse_cookie_header((req.headers or {}).get("cookie", "")).items():
            decoded = decoder.decode_candidates(value)
            if decoded and decoded.signature:
                add("high", "cookie", name, value, "Request", decoded)

        for name, value in (req.headers or {}).items():
            if name in SKIP_HEADERS or name == "cookie":
                continue
            decoded = decoder.decode_candidates(value)
            if decoded and decoded.signature:
                add("high", "header", name, value, "Request", decoded)

        ctype = (req.content_type or "").lower()
        if ctype in SERIALIZED_CONTENT_TYPES:
            kind = SERIALIZED_CONTENT_TYPES[ctype]
            mark(signatures.by_content_type(ctype) or signatures.by_kind(kind), f"Request body (Content-Type: {ctype})")
            findings.append(Finding(
                module="deserialization",
                severity="high",
                title=f"Deserialization: {kind} Request Body",
                location=req.url,
                evidence=f"Request Content-Type: {ctype}",
                vector_hint="Endpoint consumes native serialized objects — highest-risk deserialization sink",
            ))
        elif req.body:
            body = req.body.strip()
            text_kind = classify_text(body[:4096])
            if text_kind:
                signature = signatures.by_kind(text_kind)
                decoded = decoder.DecodedPayload(original=body, decoded_text=body, signature=signature)
                add("high", "body", "(raw body)", body, "Request", decoded)
            else:
                decoded = decoder.decode_candidates(body[:8192])
                if decoded and decoded.signature:
                    add("high", "body", "(raw body)", body, "Request", decoded)

        rctype = (resp.content_type or "").lower()
        if rctype in SERIALIZED_CONTENT_TYPES:
            mark(
                signatures.by_content_type(rctype) or signatures.by_kind(SERIALIZED_CONTENT_TYPES[rctype]),
                f"Response body (Content-Type: {rctype})",
            )
            findings.append(Finding(
                module="deserialization",
                severity="medium",
                title=f"Deserialization: {SERIALIZED_CONTENT_TYPES[rctype]} Response Body",
                location=req.url,
                evidence=f"Response Content-Type: {rctype}",
                vector_hint="Server emits native serialized objects; the same format is often accepted back on request",
            ))

        for cookie in parse_set_cookies((resp.headers or {}).get("set-cookie", "")):
            decoded = decoder.decode_candidates(cookie["value"])
            if decoded and decoded.signature:
                add("medium", "cookie", cookie["name"], cookie["value"], "Response", decoded)

        return findings