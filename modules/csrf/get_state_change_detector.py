import re
from typing import List
from core.models import HttpRecord, Finding
from modules.csrf.common import is_static, url_path

ACTION_WORDS = {
    "delete", "remove", "destroy", "disable", "deactivate", "approve", "reject",
    "transfer", "cancel", "revoke", "unsubscribe", "ban", "unban", "promote",
    "demote", "reset", "withdraw", "confirm", "close", "purge",
}
ACTION_PARAMS = ("action", "do", "op", "cmd", "operation", "method")


class CsrfGetStateChangeDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        req = record.request
        if (req.method or "").upper() != "GET" or is_static(req.url):
            return []
        if not (req.headers or {}).get("cookie"):
            return []
        if record.response.status >= 400:
            return []

        path = url_path(req.url).lower()
        tokens = {t for t in re.split(r"[^a-z0-9]+", path) if t}
        hits = tokens & ACTION_WORDS

        for name, value in (req.params or {}).items():
            if str(name).lower() in ACTION_PARAMS and isinstance(value, str):
                if value.lower() in ACTION_WORDS:
                    hits.add(value.lower())

        if not hits:
            return []

        return [Finding(
            module="csrf",
            severity="medium",
            title="CSRF: State-Changing Action Over GET",
            location=req.url,
            evidence=f"GET {url_path(req.url)} — action keyword(s): {', '.join(sorted(hits))}",
            vector_hint="GET requests are sent cross-site via <img>, <a> or redirects; test whether this action executes without a token",
        )]
