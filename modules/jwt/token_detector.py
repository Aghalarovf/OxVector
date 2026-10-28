from typing import List, Tuple
from core.models import HttpRecord, Finding
from modules.jwt.jwt_decoder import find_tokens, decode_token, assess_algorithm


def _collect_sources(record: HttpRecord) -> List[Tuple[str, str]]:
    sources = [("request URL", record.request.url or "")]

    for name, value in (record.request.headers or {}).items():
        text = str(value)
        if name == "cookie":
            for part in text.split(";"):
                cookie_name, _, cookie_value = part.partition("=")
                sources.append((f"request cookie '{cookie_name.strip()}'", cookie_value))
        else:
            sources.append((f"request header '{name}'", text))

    sources.append(("request body", record.request.body or ""))

    for name, value in (record.response.headers or {}).items():
        text = str(value)
        if name == "set-cookie":
            for line in text.splitlines() or [text]:
                cookie_name, _, cookie_value = line.partition("=")
                sources.append((f"response cookie '{cookie_name.strip()}'", cookie_value))
        else:
            sources.append((f"response header '{name}'", text))

    sources.append(("response body", record.response.body or ""))
    return sources


class JwtTokenDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        for token, places in find_tokens(_collect_sources(record)).items():
            decoded = decode_token(token)
            algorithm = decoded["algorithm"]
            title = (
                f"JWT Detected (alg: {algorithm})"
                if algorithm
                else "JWT Detected (header not decodable)"
            )
            findings.append(Finding(
                module="jwt",
                severity="medium",
                title=title,
                location=record.request.url,
                evidence="Found in: " + ", ".join(places),
                vector_hint=None,
                extra={"jwt": decoded},
            ))
            for severity, warning_title, warning_text in assess_algorithm(
                algorithm, decoded["signature_length"]
            ):
                findings.append(Finding(
                    module="jwt",
                    severity=severity,
                    title=warning_title,
                    location=record.request.url,
                    evidence=f"{warning_text}. Found in: " + ", ".join(places),
                    vector_hint=None,
                ))
        return findings