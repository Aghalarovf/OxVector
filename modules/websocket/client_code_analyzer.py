from typing import List
from core.models import HttpRecord, Finding
from modules.websocket.common import JS_WS_RE


class WebsocketClientCodeAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        resp = record.response
        body = resp.body or ""
        ctype = (resp.content_type or "").lower()
        if not body or "WebSocket" not in body:
            return []
        if not ("html" in ctype or "javascript" in ctype or "ecmascript" in ctype):
            return []

        findings = []
        seen = set()
        for m in JS_WS_RE.finditer(body):
            target = m.group(1)
            if target in seen:
                continue
            seen.add(target)
            lowered = target.lower()
            if lowered.startswith("ws://"):
                findings.append(Finding(
                    module="websocket",
                    severity="medium",
                    title="WebSocket: Client Code Opens ws:// Connection",
                    location=record.request.url,
                    evidence=f"new WebSocket(\"{target}\")",
                    vector_hint="Client hardcodes an unencrypted WebSocket endpoint; also blocked as mixed content on HTTPS pages",
                ))
            if any(k in lowered for k in ("token=", "jwt=", "access_token", "apikey=", "api_key=")):
                findings.append(Finding(
                    module="websocket",
                    severity="medium",
                    title="WebSocket: Client Code Sends Credential in URL",
                    location=record.request.url,
                    evidence=f"new WebSocket(\"{target[:80]}\")",
                    vector_hint="Credentials placed in the WebSocket URL leak via logs and proxies",
                ))
            if lowered.startswith(("ws://", "wss://")):
                findings.append(Finding(
                    module="websocket",
                    severity="info",
                    title="WebSocket: Endpoint Discovered in Client Code",
                    location=record.request.url,
                    evidence=f"WebSocket endpoint: {target[:80]}",
                    vector_hint="Test the endpoint directly: authentication, Origin validation, message authorization and input handling",
                ))
        return findings
