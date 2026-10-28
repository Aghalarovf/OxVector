from typing import List
from core.models import HttpRecord, Finding
from modules.oauth.common import host_of, param

LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1")


class OauthAuthorizationRequestAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        req = record.request
        if (req.method or "").upper() not in ("GET", "POST"):
            return []

        client_id = param(record, "client_id")
        response_type = param(record, "response_type")
        if not client_id or not response_type:
            return []

        findings = []
        rtype = str(response_type).lower().split()
        state = param(record, "state")
        redirect_uri = param(record, "redirect_uri")
        challenge = param(record, "code_challenge")
        method = (param(record, "code_challenge_method") or "").lower()
        scope = str(param(record, "scope") or "")

        def add(sev, title, evidence, hint):
            findings.append(Finding(
                module="oauth",
                severity=sev,
                title=f"OAuth: {title}",
                location=req.url,
                evidence=evidence,
                vector_hint=hint,
            ))

        if not state:
            add("medium", "Authorization Request Without state Parameter",
                "Authorization request has no state parameter",
                "Missing state allows login CSRF and authorization-response injection — replay a forged callback")

        if "token" in rtype or "id_token" in rtype:
            add("medium", "Implicit Flow in Use",
                f"response_type={response_type}",
                "Tokens are returned in the URL fragment; prefer authorization code with PKCE and check for token leakage via redirects")

        if "code" in rtype and not challenge:
            add("low", "Authorization Code Flow Without PKCE",
                "No code_challenge in authorization request",
                "Without PKCE a stolen authorization code can be redeemed by an attacker (especially for public clients)")

        if challenge and method == "plain":
            add("low", "PKCE Uses plain Method",
                "code_challenge_method=plain",
                "plain provides no protection if the request is observed; require S256")

        if redirect_uri:
            ru = str(redirect_uri)
            lowered = ru.lower()
            host = host_of(ru)
            if "*" in ru:
                add("high", "Wildcard in redirect_uri",
                    f"redirect_uri={ru}",
                    "Wildcard redirect URIs let attackers receive codes and tokens on arbitrary hosts")
            elif lowered.startswith("http://") and host not in LOCAL_HOSTS:
                add("medium", "Insecure redirect_uri Scheme",
                    f"redirect_uri uses http:// ({host})",
                    "Authorization response travels over cleartext HTTP and can be intercepted")
            elif host in LOCAL_HOSTS:
                add("low", "Localhost redirect_uri",
                    f"redirect_uri points to {host}",
                    "Localhost redirects registered on production clients can be abused if another local service listens")
            add("info", "redirect_uri Parameter Present",
                "redirect_uri is client-controlled in the authorization request",
                "Test redirect_uri validation: subdomains, path traversal, parameter pollution, open redirects on the client domain")

        if "offline_access" in scope.split():
            add("low", "offline_access Scope Requested",
                "scope includes offline_access",
                "Long-lived refresh tokens raise the impact of token theft; verify rotation and revocation")

        return findings
