import re
import json
import base64
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

JWT_PATTERN = re.compile(
    r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
)
TIME_CLAIMS = ("exp", "iat", "nbf", "auth_time")
SYMMETRIC_ALGORITHMS = {"HS256", "HS384", "HS512"}
ASYMMETRIC_ALGORITHMS = {
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512", "ES256K",
    "EDDSA",
}


def _b64url_decode(segment: str) -> Optional[bytes]:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception:
        return None


def _decode_json_segment(segment: str) -> Optional[dict]:
    raw = _b64url_decode(segment)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _format_time(value) -> Optional[str]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        moment = datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def decode_token(token: str) -> dict:
    header_segment, payload_segment, signature_segment = token.split(".")
    header = _decode_json_segment(header_segment)
    payload = _decode_json_segment(payload_segment)
    signature = _b64url_decode(signature_segment) if signature_segment else b""

    timestamps = {}
    if payload:
        for claim in TIME_CLAIMS:
            if claim in payload:
                formatted = _format_time(payload[claim])
                if formatted:
                    timestamps[claim] = formatted

    algorithm = None
    if header and "alg" in header:
        algorithm = str(header["alg"])

    return {
        "token": token,
        "algorithm": algorithm,
        "header": header,
        "payload": payload,
        "timestamps": timestamps,
        "signature_length": len(signature) if signature is not None else None,
        "signature_hex": signature.hex() if signature else "",
    }


def assess_algorithm(algorithm: Optional[str], signature_length: Optional[int]) -> List[Tuple[str, str, str]]:
    if algorithm is None:
        return []

    warnings = []
    normalized = algorithm.strip().upper()

    if normalized == "NONE":
        warnings.append((
            "critical",
            f"Weak JWT Algorithm: {algorithm}",
            f"alg '{algorithm}' - token is unsigned, no cryptographic signature is applied",
        ))
    elif normalized in SYMMETRIC_ALGORITHMS:
        warnings.append((
            "medium",
            f"Symmetric JWT Algorithm: {algorithm}",
            f"alg '{algorithm}' - HMAC with a shared secret, security depends entirely on the secrecy and strength of that secret",
        ))
    elif normalized not in ASYMMETRIC_ALGORITHMS:
        warnings.append((
            "medium",
            f"Unrecognized JWT Algorithm: {algorithm}",
            f"alg '{algorithm}' is not a standard JWS algorithm",
        ))

    if normalized != "NONE" and signature_length == 0:
        warnings.append((
            "high",
            "JWT Has Empty Signature",
            f"alg '{algorithm}' is declared but the signature segment is empty - token is effectively unsigned",
        ))

    return warnings


def find_tokens(sources: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for place, text in sources:
        if not text:
            continue
        for match in JWT_PATTERN.finditer(text):
            places = found.setdefault(match.group(0), [])
            if place not in places:
                places.append(place)
    return found