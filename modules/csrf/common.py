import re
from core.http_utils import (
    STATIC_EXTENSIONS,
    SESSION_COOKIE_RE,
    url_path,
    is_static,
    parse_set_cookies,
)

TOKEN_NAME_RE = re.compile(
    r"csrf|xsrf|authenticity_token|anti[-_]?forgery|requestverificationtoken|"
    r"_token\b|^token$|nonce|form[-_]?key|__vit",
    re.IGNORECASE,
)

STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")



def has_token_name(name: str) -> bool:
    return bool(TOKEN_NAME_RE.search(name or ""))
