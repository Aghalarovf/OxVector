import re
from urllib.parse import urlparse

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".map", ".webp", ".mp4", ".mp3", ".pdf",
)

SESSION_COOKIE_RE = re.compile(
    r"sess|sid\b|auth|token|jwt|login|jsessionid|phpsessid|connect\.sid|"
    r"asp\.net|laravel|remember|user",
    re.IGNORECASE,
)


def url_path(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_static(url: str) -> bool:
    return url_path(url).lower().endswith(STATIC_EXTENSIONS)


def parse_set_cookies(raw: str):
    cookies = []
    if not raw:
        return cookies
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        attrs = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            elif part:
                attrs[part.strip().lower()] = ""
        cookies.append({"name": name.strip(), "value": value, "attrs": attrs})
    return cookies


def parse_cookie_header(raw: str):
    out = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out
