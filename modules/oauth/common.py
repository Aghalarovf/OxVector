import re
from urllib.parse import urlparse, parse_qs

CALLBACK_PATH_RE = re.compile(r"callback|redirect|oauth|signin|sso|authorize|auth/|openid|oidc", re.IGNORECASE)
TOKEN_PARAMS = ("access_token", "id_token", "refresh_token")


def param(record, name: str):
    v = (record.request.params or {}).get(name)
    if isinstance(v, list):
        v = v[0] if v else None
    return v


def query_params(url: str):
    try:
        p = urlparse(url)
        out = {}
        for k, v in parse_qs(p.query, keep_blank_values=True).items():
            out[k.lower()] = v[0]
        for k, v in parse_qs(p.fragment, keep_blank_values=True).items():
            out.setdefault(k.lower(), v[0])
        return out
    except Exception:
        return {}


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
