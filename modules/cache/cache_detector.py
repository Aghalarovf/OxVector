from typing import List, Optional, Tuple
from core.models import HttpRecord, Finding

CACHE_STATUS_HEADERS = ("cf-cache-status", "x-cache", "x-cache-status", "x-varnish")

CACHE_STATUS_HIT_VALUES    = ("hit", "expired", "stale", "revalidated", "tcp_hit", "refresh_hit")
CACHE_STATUS_MISS_VALUES   = ("miss", "tcp_miss", "refresh_miss")
CACHE_STATUS_BYPASS_VALUES = ("bypass", "dynamic", "disabled", "uncacheable", "no-cache")

SURROGATE_HEADERS = (
    "surrogate-control",
    "cdn-cache-control",
    "cloudflare-cdn-cache-control",
    "fastly-surrogate-control",
)

SAFE_CC_DIRECTIVES = ("no-store", "no-cache", "private")

SUSPICIOUS_UNKEYED_HEADERS = (
    "x-forwarded-host",
    "x-forwarded-scheme",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-host",
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-for",
    "x-real-ip",
    "x-custom-ip-authorization",
    "x-http-method-override",
    "x-original-method",
    "x-override-url",
    "referer",
    "user-agent",
)

CDN_PRESENCE_HEADERS = (
    "cf-cache-status",
    "cf-ray",
    "x-cache",
    "x-varnish",
    "x-served-by",
    "x-cache-hits",
    "via",
    "age",
    "surrogate-control",
    "cdn-cache-control",
)

_W_CDN_SIGNAL   = 10
_W_PUBLIC_CC    = 20
_W_POSITIVE_TTL = 15
_W_NO_CACHE_CDN = 10
_W_HEURISTIC    = 25
_W_NO_VARY      = 30
_W_UNKEYED_ONLY = 25
_W_MIXED_VARY   = 12
_W_KEYED_BONUS  = -10
_W_LONG_AGE     = 10
_W_SURROGATE    = 15


def _get_header(headers: dict, name: str) -> Optional[str]:
    return headers.get(name.lower())


def _cc_directives(headers: dict) -> List[str]:
    cc = _get_header(headers, "cache-control") or ""
    return [d.strip().lower() for d in cc.split(",") if d.strip()]


def _is_safe_cc(directives: List[str]) -> bool:
    return any(d in SAFE_CC_DIRECTIVES for d in directives)


def _is_publicly_cached(directives: List[str]) -> bool:
    if "public" in directives:
        return True
    return any(d.startswith("max-age=") and d != "max-age=0" for d in directives)


def _cache_status(headers: dict) -> Optional[str]:
    for h in CACHE_STATUS_HEADERS:
        val = _get_header(headers, h)
        if val:
            v = val.strip().lower()
            if v in CACHE_STATUS_HIT_VALUES:
                return "hit"
            if v in CACHE_STATUS_MISS_VALUES:
                return "miss"
            if v in CACHE_STATUS_BYPASS_VALUES:
                return "bypass"
    return None


def _age_seconds(headers: dict) -> Optional[int]:
    age = _get_header(headers, "age")
    if age:
        try:
            return int(age)
        except ValueError:
            pass
    return None


def _vary_fields(headers: dict) -> List[str]:
    vary = _get_header(headers, "vary") or ""
    if vary.strip() == "*":
        return ["*"]
    return [v.strip().lower() for v in vary.split(",") if v.strip()]


def _max_age(directives: List[str]) -> Optional[int]:
    for d in directives:
        if d.startswith("max-age="):
            try:
                return int(d.split("=", 1)[1])
            except ValueError:
                pass
    return None


def _surrogate_max_age(headers: dict) -> Optional[Tuple[str, int]]:
    for h in SURROGATE_HEADERS:
        val = _get_header(headers, h)
        if val:
            for part in val.split(","):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        return (h, int(part.split("=", 1)[1]))
                    except ValueError:
                        pass
            return (h, -1)
    return None


def _has_heuristic_caching_risk(headers: dict, cc_directives: List[str]) -> bool:
    if cc_directives:
        return False
    last_modified = _get_header(headers, "last-modified")
    return bool(last_modified)


def _active_cdn_signals(headers: dict) -> List[str]:
    return [h for h in CDN_PRESENCE_HEADERS if _get_header(headers, h) is not None]


def _evidence_lines(resp_headers: dict) -> List[str]:
    lines = []
    cc = _get_header(resp_headers, "cache-control")
    if cc:
        lines.append(f"Cache-Control: {cc}")
    for h in CACHE_STATUS_HEADERS:
        v = _get_header(resp_headers, h)
        if v:
            lines.append(f"{h}: {v}")
    for h in SURROGATE_HEADERS:
        v = _get_header(resp_headers, h)
        if v:
            lines.append(f"{h}: {v}")
    vary = _get_header(resp_headers, "vary")
    if vary:
        lines.append(f"Vary: {vary}")
    age = _get_header(resp_headers, "age")
    if age:
        lines.append(f"Age: {age}")
    last_mod = _get_header(resp_headers, "last-modified")
    if last_mod:
        lines.append(f"Last-Modified: {last_mod}")
    return lines


def _compute_risk_score(
    cc: List[str],
    vary: List[str],
    cs: Optional[str],
    age: Optional[int],
    surrogate: Optional[Tuple[str, int]],
    cdn_signals: List[str],
    heuristic_risk: bool,
    unkeyed: List[str],
    keyed_only: bool,
) -> Tuple[int, List[str]]:
    score = 0
    notes = []

    score += min(len(cdn_signals) * _W_CDN_SIGNAL, 30)
    if cdn_signals:
        notes.append(f"CDN active ({len(cdn_signals)} signals: {', '.join(cdn_signals[:3])})")

    if "public" in cc:
        score += _W_PUBLIC_CC
        notes.append("Cache-Control: public")
    if any(d.startswith("max-age=") and d != "max-age=0" for d in cc):
        score += _W_POSITIVE_TTL
        notes.append("Positive TTL (max-age)")
    if any(d.startswith("s-maxage=") and d != "s-maxage=0" for d in cc):
        score += _W_POSITIVE_TTL
        notes.append("Positive CDN TTL (s-maxage)")

    if "no-cache" in cc and cdn_signals:
        score += _W_NO_CACHE_CDN
        notes.append("no-cache present but CDN active — CDN may ignore the directive")

    if surrogate:
        score += _W_SURROGATE
        h_name, ttl = surrogate
        ttl_str = f"max-age={ttl}" if ttl >= 0 else "active (TTL unknown)"
        notes.append(f"Surrogate header active: {h_name}: {ttl_str}")

    if heuristic_risk:
        score += _W_HEURISTIC
        notes.append("Heuristic caching risk — no Cache-Control, Last-Modified present")

    if not vary:
        score += _W_NO_VARY
        notes.append("No Vary header (worst case)")
    elif unkeyed and not keyed_only:
        score += _W_MIXED_VARY
        notes.append(f"Mixed Vary (unkeyed+keyed): {', '.join(unkeyed)}")
    elif unkeyed:
        score += _W_UNKEYED_ONLY
        notes.append(f"Unkeyed-only Vary: {', '.join(unkeyed)}")
    elif keyed_only:
        score += _W_KEYED_BONUS
        notes.append("All suspicious headers are keyed (bonus)")

    if age is not None and age > 3600:
        score += _W_LONG_AGE
        notes.append(f"Long cache age: {age}s ({age // 3600}h)")

    score = max(0, min(100, score))
    return score, notes


def _risk_level(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "safe"


class _CacheState:
    GREEN_NO_CACHE    = "green_no_cache"
    GREEN_SAFE        = "green_safe"
    BLUE_CONDITIONAL  = "blue_conditional"
    YELLOW_HEURISTIC  = "yellow_heuristic"
    RED_RISKY         = "red_risky"
    RED_NO_VARY       = "red_no_vary"
    RED_ENCODING_ONLY = "red_encoding_only"
    RED_SURROGATE     = "red_surrogate"
    UNKNOWN           = "unknown"


def _compute_and_store_risk(
    meta: dict, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh,
    unkeyed=None, keyed_only=False
):
    if unkeyed is None:
        unkeyed = [h for h in SUSPICIOUS_UNKEYED_HEADERS if h in reqh and h not in set(vary)]
    score, notes = _compute_risk_score(
        cc=cc, vary=vary, cs=cs, age=age,
        surrogate=surrogate, cdn_signals=cdn_sigs,
        heuristic_risk=heuristic,
        unkeyed=unkeyed, keyed_only=keyed_only,
    )
    meta["risk_score"] = score
    meta["risk_level"] = _risk_level(score)
    meta["risk_notes"] = notes


def _classify(record: HttpRecord):
    rh   = record.response.headers
    reqh = record.request.headers

    cc        = _cc_directives(rh)
    vary      = _vary_fields(rh)
    cs        = _cache_status(rh)
    age       = _age_seconds(rh)
    surrogate = _surrogate_max_age(rh)
    cdn_sigs  = _active_cdn_signals(rh)
    heuristic = _has_heuristic_caching_risk(rh, cc)

    meta: dict = {}
    cc_raw   = _get_header(rh, "cache-control")
    vary_raw = _get_header(rh, "vary")
    if cc_raw:          meta["cc_raw"]          = cc_raw
    if vary_raw:        meta["vary_raw"]         = vary_raw
    if cs:              meta["cache_status_raw"] = cs
    if age is not None: meta["age_seconds"]      = age
    if cdn_sigs:        meta["cdn_signals"]      = cdn_sigs
    if heuristic:       meta["heuristic_risk"]   = True
    if surrogate:
        meta["surrogate_header"]  = surrogate[0]
        meta["surrogate_max_age"] = surrogate[1]

    surrogate_active = surrogate is not None and surrogate[1] != 0

    if not surrogate_active:
        if _is_safe_cc(cc) and not cdn_sigs:
            return _CacheState.GREEN_NO_CACHE, meta
        if _is_safe_cc(cc) and cdn_sigs:
            if "no-store" in cc:
                return _CacheState.GREEN_NO_CACHE, meta
            _compute_and_store_risk(meta, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh)
            return _CacheState.BLUE_CONDITIONAL, meta

    if vary == ["*"]:
        return _CacheState.GREEN_NO_CACHE, meta

    if cs == "bypass":
        return _CacheState.GREEN_NO_CACHE, meta

    if heuristic and not _is_safe_cc(cc):
        _compute_and_store_risk(meta, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh)
        return _CacheState.YELLOW_HEURISTIC, meta

    if surrogate_active:
        _compute_and_store_risk(meta, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh)
        return _CacheState.RED_SURROGATE, meta

    publicly_cached = _is_publicly_cached(cc)
    has_age         = age is not None and age >= 0
    has_status      = cs in ("hit", "miss")
    is_cached       = publicly_cached or has_age or has_status

    if not is_cached:
        return _CacheState.UNKNOWN, meta

    max_age_val = _max_age(cc)
    if max_age_val is not None:
        meta["max_age"] = max_age_val

    if not vary:
        unkeyed = [h for h in SUSPICIOUS_UNKEYED_HEADERS if h in reqh]
        meta["unkeyed_headers"] = unkeyed
        _compute_and_store_risk(meta, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh)
        return _CacheState.RED_NO_VARY, meta

    if vary == ["accept-encoding"]:
        unkeyed = [h for h in SUSPICIOUS_UNKEYED_HEADERS if h in reqh]
        meta["unkeyed_headers"] = unkeyed
        _compute_and_store_risk(meta, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh)
        return _CacheState.RED_ENCODING_ONLY, meta

    keyed = set(vary)
    unkeyed = [h for h in SUSPICIOUS_UNKEYED_HEADERS if h in reqh and h not in keyed]
    keyed_suspicious = [h for h in SUSPICIOUS_UNKEYED_HEADERS if h in reqh and h in keyed]
    keyed_only = bool(keyed_suspicious) and not bool(unkeyed)

    meta["keyed_headers"]   = sorted(keyed)
    meta["unkeyed_headers"] = unkeyed
    if keyed_suspicious:
        meta["keyed_suspicious"] = keyed_suspicious

    _compute_and_store_risk(meta, cc, vary, cs, age, surrogate, cdn_sigs, heuristic, reqh,
                            unkeyed=unkeyed, keyed_only=keyed_only)

    if unkeyed:
        return _CacheState.RED_RISKY, meta

    return _CacheState.GREEN_SAFE, meta


class CacheDetector:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        findings = []
        state, meta = _classify(record)
        url  = record.request.url
        evid = "\n".join(_evidence_lines(record.response.headers))

        score       = meta.get("risk_score", 0)
        risk_level  = meta.get("risk_level", "safe")
        risk_notes  = meta.get("risk_notes", [])
        score_badge = f"[Risk Score: {score}/100 — {risk_level.upper()}]"

        if state == _CacheState.GREEN_NO_CACHE:
            return findings

        if state == _CacheState.BLUE_CONDITIONAL:
            cdn_list = ", ".join(meta.get("cdn_signals", []))
            findings.append(Finding(
                module="cache",
                severity="low",
                title="Cache Poisoning: no-cache Present But CDN Active — Conditional Risk",
                location=url,
                evidence=evid + f"\nActive CDN signals: {cdn_list}\n{score_badge}",
                vector_hint=(
                    "Cache-Control: no-cache instructs clients to revalidate, but does NOT "
                    "prevent CDN caching. Some CDNs (Cloudflare, Fastly, Varnish) can ignore "
                    "no-cache and serve cached responses. If Cf-Cache-Status shows HIT with "
                    "no-cache present, the CDN is bypassing the directive. "
                    f"Risk notes: {'; '.join(risk_notes)}"
                ),
                confidence="candidate",
                extra=meta,
            ))
            return findings

        if state == _CacheState.UNKNOWN:
            return findings

        if state == _CacheState.YELLOW_HEURISTIC:
            last_mod = record.response.headers.get("last-modified", "present")
            findings.append(Finding(
                module="cache",
                severity="medium",
                title="Cache Poisoning: Heuristic Caching Risk — No Cache-Control, Last-Modified Present",
                location=url,
                evidence=evid + f"\n{score_badge}",
                vector_hint=(
                    "RFC 7234 §4.2.2: When Cache-Control is absent and Last-Modified is present, "
                    "CDNs and proxies may apply heuristic caching: implicit TTL ≈ "
                    "(Date − Last-Modified) × 0.1. No cache-related headers are visible, making "
                    "this the most invisible cache poisoning surface. "
                    f"Last-Modified: {last_mod}. "
                    f"Risk notes: {'; '.join(risk_notes)}"
                ),
                confidence="candidate",
                extra=meta,
            ))
            return findings

        if state == _CacheState.RED_SURROGATE:
            surr_h   = meta.get("surrogate_header", "surrogate-control")
            surr_age = meta.get("surrogate_max_age", -1)
            ttl_str  = f"max-age={surr_age}" if surr_age >= 0 else "active (TTL unknown)"
            findings.append(Finding(
                module="cache",
                severity="high",
                title=f"Cache Poisoning: {surr_h} Overrides Cache-Control",
                location=url,
                evidence=evid + f"\n{score_badge}",
                vector_hint=(
                    f"{surr_h}: {ttl_str} takes precedence over Cache-Control at the CDN layer "
                    "(Fastly, Varnish, Cloudflare Enterprise). Even if Cache-Control says no-cache "
                    "or no-store, the CDN will cache according to Surrogate-Control. "
                    f"Risk notes: {'; '.join(risk_notes)}"
                ),
                confidence="likely",
                extra=meta,
            ))
            return findings

        if state == _CacheState.GREEN_SAFE:
            keyed = meta.get("keyed_headers", [])
            ks    = meta.get("keyed_suspicious", [])
            detail = (
                f"Vary covers: {', '.join(keyed)}. "
                + (f"Suspicious headers that ARE keyed: {', '.join(ks)}. " if ks else "")
                + "No unkeyed injection surface found."
            )
            findings.append(Finding(
                module="cache",
                severity="info",
                title="Cache Active: All Suspicious Headers Are Keyed — Safe",
                location=url,
                evidence=evid + f"\n{score_badge}",
                vector_hint=detail,
                confidence="confirmed",
                extra=meta,
            ))
            return findings

        if state == _CacheState.RED_NO_VARY:
            unkeyed = meta.get("unkeyed_headers", [])
            if unkeyed:
                findings.append(Finding(
                    module="cache",
                    severity="high",
                    title="Cache Poisoning: No Vary Header — Suspicious Request Headers Present",
                    location=url,
                    evidence=evid + f"\nSuspicious request headers: {', '.join(unkeyed)}\n{score_badge}",
                    vector_hint=(
                        "Response is cached and has NO Vary header — every request header is "
                        f"unkeyed. The following headers were sent in the request and could be "
                        f"used to inject a poisoned cache entry: {', '.join(unkeyed)}. "
                        f"Risk notes: {'; '.join(risk_notes)}"
                    ),
                    confidence="candidate",
                    extra=meta,
                ))
            else:
                findings.append(Finding(
                    module="cache",
                    severity="medium",
                    title="Cache Poisoning: Response Cached Without Any Vary Header",
                    location=url,
                    evidence=evid + f"\n{score_badge}",
                    vector_hint=(
                        "Response is cached and has no Vary header. "
                        "Any unkeyed request header (X-Forwarded-Host, X-Host, Referer, etc.) "
                        "could be used to poison the cache. "
                        f"Risk notes: {'; '.join(risk_notes)}"
                    ),
                    confidence="candidate",
                    extra=meta,
                ))
            return findings

        if state == _CacheState.RED_ENCODING_ONLY:
            unkeyed = meta.get("unkeyed_headers", [])
            if unkeyed:
                findings.append(Finding(
                    module="cache",
                    severity="high",
                    title="Cache Poisoning: Vary: Accept-Encoding Only — Unkeyed Headers Present",
                    location=url,
                    evidence=evid + f"\nUnkeyed request headers: {', '.join(unkeyed)}\n{score_badge}",
                    vector_hint=(
                        "Vary is limited to Accept-Encoding — all other request headers are "
                        f"unkeyed. Headers present in this request that could poison the cache: "
                        f"{', '.join(unkeyed)}. "
                        "Note: Many CDNs (Cloudflare, Fastly) normalise Accept-Encoding before "
                        "caching, so even this field may effectively be unkeyed at the CDN layer. "
                        f"Risk notes: {'; '.join(risk_notes)}"
                    ),
                    confidence="candidate",
                    extra=meta,
                ))
            else:
                findings.append(Finding(
                    module="cache",
                    severity="medium",
                    title="Cache Poisoning: Vary: Accept-Encoding Only",
                    location=url,
                    evidence=evid + f"\n{score_badge}",
                    vector_hint=(
                        "Only Accept-Encoding is keyed. All other request headers are unkeyed "
                        "and could be injected to create a poisoned cache entry. "
                        "Additionally, many CDNs normalise Accept-Encoding so it may not "
                        "effectively separate cache entries at the CDN layer. "
                        f"Risk notes: {'; '.join(risk_notes)}"
                    ),
                    confidence="candidate",
                    extra=meta,
                ))
            return findings

        if state == _CacheState.RED_RISKY:
            unkeyed = meta.get("unkeyed_headers", [])
            keyed   = meta.get("keyed_headers", [])
            findings.append(Finding(
                module="cache",
                severity="high",
                title="Cache Poisoning: Suspicious Request Headers Not Covered by Vary",
                location=url,
                evidence=evid + f"\nUnkeyed suspicious headers: {', '.join(unkeyed)}\n{score_badge}",
                vector_hint=(
                    f"Response is cached. Vary covers {keyed} but does NOT include: "
                    f"{', '.join(unkeyed)}. These headers are present in the request but "
                    "unkeyed — a poisoned value could be served to all subsequent users. "
                    f"Risk notes: {'; '.join(risk_notes)}"
                ),
                confidence="candidate",
                extra=meta,
            ))
            return findings

        return findings