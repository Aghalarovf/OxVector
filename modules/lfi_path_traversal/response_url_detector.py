from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from core.models import HttpRecord, Finding
from modules.lfi_path_traversal.pattern_url_detector import FILE_SERVING_PATTERNS

ENDPOINT_PATTERNS = [
    (pattern, label)
    for pattern, label in FILE_SERVING_PATTERNS
    if label != "Direct file path in URL"
]

PATH_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./%~:@"
)
QUERY_STOP = frozenset(" \t\r\n\"'<>\\)")
MAX_PATH_LOOKBEHIND = 300
MAX_QUERY_LENGTH = 2000
TRAILING_PUNCTUATION = ".,;:]}"
SCANNED_HEADERS = ("location", "content-location", "link", "refresh")


def _normalize(text: str) -> str:
    return (
        text.replace("\\/", "/")
        .replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("\\u0026", "&")
    )


def extract_url_candidates(text: str) -> List[str]:
    candidates = []
    position = 0
    while True:
        mark = text.find("?", position)
        if mark == -1:
            break
        position = mark + 1

        begin = mark
        while (
            begin > 0
            and mark - begin < MAX_PATH_LOOKBEHIND
            and text[begin - 1] in PATH_CHARS
        ):
            begin -= 1

        end = mark + 1
        while (
            end < len(text)
            and end - mark < MAX_QUERY_LENGTH
            and text[end] not in QUERY_STOP
        ):
            end += 1

        candidate = text[begin:end].rstrip(TRAILING_PUNCTUATION)
        query = candidate.partition("?")[2]
        if begin == mark or "=" not in query:
            continue
        candidates.append(candidate)
    return candidates


class LfiResponseUrlDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        sources = []
        for name, value in (record.response.headers or {}).items():
            if name in SCANNED_HEADERS:
                sources.append((f"response header '{name}'", str(value)))
        sources.append(("response body", record.response.body or ""))

        base = record.request.url or ""
        groups: Dict[Tuple, dict] = {}

        for place, text in sources:
            if not text:
                continue
            for candidate in extract_url_candidates(_normalize(text)):
                try:
                    resolved = urljoin(base, candidate)
                    parsed = urlparse(resolved)
                    keys = tuple(sorted(parse_qs(parsed.query, keep_blank_values=True)))
                except ValueError:
                    continue
                for pattern, label in ENDPOINT_PATTERNS:
                    if not pattern.search(resolved):
                        continue
                    group = groups.setdefault(
                        (label, parsed.netloc, parsed.path, keys),
                        {"urls": [], "places": []},
                    )
                    if resolved not in group["urls"]:
                        group["urls"].append(resolved)
                    if place not in group["places"]:
                        group["places"].append(place)

        findings = []
        for (label, netloc, path, keys), group in groups.items():
            urls = group["urls"]
            findings.append(Finding(
                module="lfi",
                severity="medium",
                title=f"Hidden File Serving Pattern in Response: {label}",
                location=record.request.url,
                evidence=(
                    f"{len(urls)} unique URL(s) on {path} "
                    f"(params: {', '.join(keys)}) found in {', '.join(group['places'])}"
                ),
                vector_hint=None,
                extra={"urls": urls},
            ))
        return findings