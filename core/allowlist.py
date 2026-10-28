import re
from typing import Optional

THIRD_PARTY_SIGNATURES = [
    (re.compile(r'__CF\$cv\$params', re.IGNORECASE), "Cloudflare Bot Management"),
    (re.compile(r'challenge-platform', re.IGNORECASE), "Cloudflare Challenge Platform"),
    (re.compile(r'googletagmanager\.com', re.IGNORECASE), "Google Tag Manager"),
    (re.compile(r'google-analytics\.com|gtag\s*\(', re.IGNORECASE), "Google Analytics"),
    (re.compile(r'connect\.facebook\.net|fbq\s*\(', re.IGNORECASE), "Facebook Pixel"),
    (re.compile(r'jquery[.-][\d.]+(?:\.min)?\.js', re.IGNORECASE), "jQuery Library"),
    (re.compile(r'cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com', re.IGNORECASE), "Public CDN Library"),
    (re.compile(r'recaptcha|grecaptcha', re.IGNORECASE), "Google reCAPTCHA"),
    (re.compile(r'hotjar\.com|hj\s*\(', re.IGNORECASE), "Hotjar Analytics"),
    (re.compile(r'youtube\.com/iframe_api|player_api\.js', re.IGNORECASE), "YouTube Player API"),
    (re.compile(r'data-reactroot|data-reactid|__NEXT_DATA__|_app-[0-9a-f]+\.js', re.IGNORECASE), "React / Next.js"),
    (re.compile(r'ng-version=|_nghost-|_ngcontent-|zone\.js', re.IGNORECASE), "Angular"),
    (re.compile(r'data-v-[0-9a-f]{6,8}|__VUE_DEVTOOLS_GLOBAL_HOOK__', re.IGNORECASE), "Vue.js"),
    (re.compile(r'webpackJsonp|__webpack_require__', re.IGNORECASE), "Webpack Bundle Runtime"),
    (re.compile(r'sentry\.io|Sentry\.init\s*\(', re.IGNORECASE), "Sentry Error Monitoring"),
    (re.compile(r'cdn\.segment\.com|analytics\.track\s*\(', re.IGNORECASE), "Segment Analytics"),
    (re.compile(r'widget\.intercom\.io|Intercom\s*\(', re.IGNORECASE), "Intercom Chat Widget"),
    (re.compile(r'js\.stripe\.com|Stripe\s*\(', re.IGNORECASE), "Stripe.js"),
    (re.compile(r'maps\.googleapis\.com', re.IGNORECASE), "Google Maps"),
    (re.compile(r'snap\.licdn\.com', re.IGNORECASE), "LinkedIn Insight Tag"),
    (re.compile(r'analytics\.tiktok\.com', re.IGNORECASE), "TikTok Pixel"),
    (re.compile(r'platform\.twitter\.com/widgets', re.IGNORECASE), "Twitter Widgets"),
    (re.compile(r'cdn\.cookielaw\.org|OneTrust', re.IGNORECASE), "OneTrust Cookie Consent"),
    (re.compile(r'js-agent\.newrelic\.com', re.IGNORECASE), "New Relic Browser Agent"),
    (re.compile(r'datadoghq-browser-agent', re.IGNORECASE), "Datadog RUM Agent"),
]

CONTEXT_WINDOW = 400


def classify_context(body: str, match_pos: int) -> Optional[str]:
    if not body:
        return None
    start = max(0, match_pos - CONTEXT_WINDOW)
    end = min(len(body), match_pos + CONTEXT_WINDOW)
    window = body[start:end]
    for pattern, vendor in THIRD_PARTY_SIGNATURES:
        if pattern.search(window):
            return vendor
    return None


def classify_body(body: str) -> Optional[str]:
    if not body:
        return None
    for pattern, vendor in THIRD_PARTY_SIGNATURES:
        if pattern.search(body):
            return vendor
    return None
