from typing import List
from core.models import HttpRecord, Finding
from modules.oauth.common import CALLBACK_PATH_RE, TOKEN_PARAMS, param, query_params
from modules.csrf.common import url_path


class OauthCallbackAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        path = url_path(req.url)

        def add(sev, title, evidence, hint):
            findings.append(Finding(
                module="oauth",
                severity=sev,
                title=f"OAuth: {title}",
                location=req.url,
                evidence=evidence,
                vector_hint=hint,
            ))

        code = param(record, "code")
        if code and (req.method or "").upper() == "GET" and CALLBACK_PATH_RE.search(path):
            if not param(record, "state"):
                add("medium", "Callback Without state Parameter",
                    f"GET {path} receives code without state",
                    "Without state validation the client accepts attacker-supplied codes — test login CSRF and account linking attacks")

        url_params = query_params(req.url)
        for name in TOKEN_PARAMS:
            if name in url_params:
                add("medium", f"{name} Exposed in URL",
                    f"{name} appears in request URL",
                    "Tokens in URLs leak through logs, browser history and Referer headers")

        referer = (req.headers or {}).get("referer", "")
        if referer:
            ref_params = query_params(referer)
            leaked = [n for n in TOKEN_PARAMS if n in ref_params]
            if "code" in ref_params and "state" in ref_params:
                leaked.append("authorization code")
            if leaked:
                add("medium", "Credential Leaked via Referer",
                    f"Referer header carries: {', '.join(leaked)}",
                    "OAuth credentials sent to third-party hosts via Referer — check Referrer-Policy and external resources on the callback page")

        location = (record.response.headers or {}).get("location", "")
        if location:
            loc_params = query_params(location)
            leaked = [n for n in TOKEN_PARAMS if n in loc_params]
            if leaked:
                add("low", "Token Returned in Redirect Location",
                    f"Location header carries: {', '.join(leaked)}",
                    "Tokens delivered by redirect URL are exposed to history, logs and intermediaries")

        if "client_secret" in url_params:
            add("high", "client_secret Exposed in URL",
                "client_secret appears in request URL",
                "Client secret sent as a query parameter is logged and cached; rotate it and send it in the POST body or Authorization header")

        return findings
