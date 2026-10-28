import json
from typing import List
from core.models import HttpRecord, Finding
from modules.oauth.common import param
from modules.csrf.common import url_path


class OauthTokenEndpointAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        req = record.request
        grant_type = param(record, "grant_type")
        if not grant_type or (req.method or "").upper() != "POST":
            return []

        path = url_path(req.url)
        grant = str(grant_type).lower()

        def add(sev, title, evidence, hint):
            findings.append(Finding(
                module="oauth",
                severity=sev,
                title=f"OAuth: {title}",
                location=req.url,
                evidence=evidence,
                vector_hint=hint,
            ))

        if grant == "password":
            add("medium", "Resource Owner Password Grant in Use",
                f"POST {path} grant_type=password",
                "Client handles user credentials directly; test brute force limits and credential stuffing protection")

        if grant == "authorization_code" and not param(record, "code_verifier"):
            add("low", "Token Request Without code_verifier",
                f"POST {path} grant_type=authorization_code without code_verifier",
                "No PKCE verifier on the code exchange — an intercepted code may be redeemable")

        if param(record, "client_secret") and not (req.headers or {}).get("authorization"):
            add("info", "client_secret Sent in Request Body",
                f"POST {path} sends client_secret in body",
                "Confirm this is a confidential server-side client; a secret in a browser or mobile app is not secret")

        if str(param(record, "redirect_uri") or "").startswith("http://"):
            add("medium", "Token Request Uses http:// redirect_uri",
                f"POST {path} redirect_uri uses http://",
                "Cleartext redirect URI registered for the client")

        resp = record.response
        body = resp.body or ""
        if resp.status == 200 and "access_token" in body:
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            if isinstance(data, dict) and "access_token" in data:
                cc = (resp.headers or {}).get("cache-control", "").lower()
                if "no-store" not in cc:
                    add("low", "Token Response Without Cache-Control: no-store",
                        f"{path} returns tokens without no-store",
                        "RFC 6749 requires no-store on token responses; intermediaries may cache access tokens")
                if data.get("refresh_token") and not data.get("expires_in"):
                    add("low", "Token Response Without expires_in",
                        f"{path} returns tokens without expires_in",
                        "Missing expiry hints at long-lived or non-expiring access tokens")
                if str(data.get("token_type", "")).lower() == "bearer" and not data.get("scope"):
                    add("info", "Token Response Without scope",
                        f"{path} omits scope in the token response",
                        "Verify the granted scope is not broader than requested")

        return findings
