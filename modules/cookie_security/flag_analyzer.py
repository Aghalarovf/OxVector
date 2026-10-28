from typing import List
from urllib.parse import urlparse
from core.models import HttpRecord, Finding
from core.http_utils import SESSION_COOKIE_RE, parse_set_cookies

LONG_LIVED_SECONDS = 30 * 24 * 3600


class CookieSecurityFlagAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        raw = (record.response.headers or {}).get("set-cookie", "")
        url = record.request.url
        https = urlparse(url).scheme.lower() == "https"

        def add(sev, title, evidence, hint):
            findings.append(Finding(
                module="cookie_security",
                severity=sev,
                title=f"Cookie Security: {title}",
                location=url,
                evidence=evidence,
                vector_hint=hint,
            ))

        for cookie in parse_set_cookies(raw):
            name = cookie["name"]
            attrs = cookie["attrs"]
            session_like = bool(SESSION_COOKIE_RE.search(name))
            lname = name.lower()

            if "secure" not in attrs:
                if session_like:
                    add("medium", "Session Cookie Without Secure Flag",
                        f"Set-Cookie: {name} has no Secure attribute",
                        "Cookie can be sent over plain HTTP and captured by a network attacker")
                elif not https:
                    add("low", "Cookie Set Over HTTP Without Secure Flag",
                        f"Set-Cookie: {name} set over HTTP without Secure",
                        "Cookies delivered over cleartext HTTP are exposed to interception")

            if session_like and "httponly" not in attrs:
                add("medium", "Session Cookie Without HttpOnly Flag",
                    f"Set-Cookie: {name} has no HttpOnly attribute",
                    "Cookie is readable from JavaScript, so any XSS can steal the session")

            if lname.startswith("__host-"):
                if "secure" not in attrs or "domain" in attrs or attrs.get("path") != "/":
                    add("low", "Invalid __Host- Cookie Prefix Usage",
                        f"{name} violates __Host- requirements (Secure, Path=/, no Domain)",
                        "Browsers reject the cookie; the prefix guarantee is not achieved")
            elif lname.startswith("__secure-") and "secure" not in attrs:
                add("low", "Invalid __Secure- Cookie Prefix Usage",
                    f"{name} lacks the Secure attribute required by its prefix",
                    "Browsers reject the cookie; the prefix guarantee is not achieved")

            if session_like and "domain" in attrs and attrs["domain"].startswith("."):
                add("low", "Session Cookie Scoped to Parent Domain",
                    f"Set-Cookie: {name}; Domain={attrs['domain']}",
                    "Every subdomain receives the cookie — a compromised or takeover-able subdomain can steal or fixate the session")

            max_age = attrs.get("max-age", "")
            if session_like and max_age.lstrip("-").isdigit() and int(max_age) > LONG_LIVED_SECONDS:
                add("low", "Long-Lived Session Cookie",
                    f"Set-Cookie: {name}; Max-Age={max_age} (over 30 days)",
                    "Persistent session cookies extend the window for theft and replay")

            samesite = attrs.get("samesite")
            if samesite is None:
                if session_like:
                    add("low", "Session Cookie Without SameSite Attribute",
                        f"Set-Cookie: {name} has no SameSite attribute",
                        "Browser default applies; an explicit SameSite=Lax or Strict reduces cross-site request forgery exposure")
            else:
                mode = samesite.strip().lower()
                if mode == "none":
                    if "secure" not in attrs:
                        add("medium", "SameSite=None Without Secure Flag",
                            f"Set-Cookie: {name}; SameSite=None without Secure",
                            "Browsers reject SameSite=None cookies that are not Secure, so the cookie is dropped or the intended policy is not applied")
                    elif session_like:
                        add("low", "Session Cookie With SameSite=None",
                            f"Set-Cookie: {name}; SameSite=None",
                            "Cookie is sent on all cross-site requests; state-changing endpoints depend entirely on CSRF tokens")
                elif mode not in ("strict", "lax"):
                    add("low", "Invalid SameSite Value",
                        f"Set-Cookie: {name}; SameSite={samesite}",
                        "Unrecognized SameSite values are ignored by browsers and fall back to default behavior")

            path = attrs.get("path")
            if session_like and not lname.startswith("__host-"):
                if path is None:
                    add("low", "Session Cookie Without Explicit Path",
                        f"Set-Cookie: {name} has no Path attribute",
                        "Path defaults to the directory of the request URL, which can scope the cookie inconsistently across endpoints")
                elif path == "/":
                    add("low", "Session Cookie Scoped to Entire Site",
                        f"Set-Cookie: {name}; Path=/",
                        "Cookie is sent to every path on the host, including less trusted applications or user-content areas sharing the origin")
            if path and not path.startswith("/"):
                add("low", "Invalid Cookie Path",
                    f"Set-Cookie: {name}; Path={path}",
                    "Path does not start with a slash, so browsers ignore it and use the default path")
        return findings