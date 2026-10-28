from typing import List, Dict, Type
from core.models import HttpRecord, Finding

from modules.xml.xml_detector import XmlDetector
from modules.xml.content_type_analyzer import XmlContentTypeAnalyzer
from modules.xml.soap_detector import XmlSoapDetector

from modules.lfi_path_traversal.file_param_detector import LfiFileParamDetector
from modules.lfi_path_traversal.extension_url_detector import LfiExtensionUrlDetector
from modules.lfi_path_traversal.pattern_url_detector import LfiPatternUrlDetector
from modules.lfi_path_traversal.response_url_detector import LfiResponseUrlDetector
from modules.lfi_path_traversal.traversal_hint_detector import LfiTraversalHintDetector

from modules.jwt.token_detector import JwtTokenDetector

from modules.file_upload.multipart_detector import FileUploadMultipartDetector
from modules.file_upload.extension_detector import FileUploadExtensionDetector
from modules.file_upload.mime_mismatch import FileUploadMimeMismatch

from modules.cache.cache_detector import CacheDetector

from modules.csrf.token_detector import CsrfTokenDetector
from modules.csrf.form_analyzer import CsrfFormAnalyzer
from modules.csrf.samesite_analyzer import CsrfSameSiteAnalyzer
from modules.csrf.get_state_change_detector import CsrfGetStateChangeDetector

from modules.clickjacking.csp_analyzer import ClickjackingCspAnalyzer
from modules.clickjacking.x_frame_analyzer import ClickjackingXFrameAnalyzer
from modules.clickjacking.samesite_analyzer import ClickjackingSameSiteAnalyzer

from modules.deserialization.serialized_object_detector import DeserializationSerializedObjectDetector
from modules.deserialization.viewstate_analyzer import DeserializationViewStateAnalyzer
from modules.deserialization.type_hint_detector import DeserializationTypeHintDetector

from modules.oauth.authorization_request_analyzer import OauthAuthorizationRequestAnalyzer
from modules.oauth.callback_analyzer import OauthCallbackAnalyzer
from modules.oauth.token_endpoint_analyzer import OauthTokenEndpointAnalyzer

from modules.websocket.handshake_analyzer import WebsocketHandshakeAnalyzer
from modules.websocket.client_code_analyzer import WebsocketClientCodeAnalyzer

from modules.info_disclosure.error_detector import InfoDisclosureErrorDetector
from modules.info_disclosure.header_leak_detector import InfoDisclosureHeaderLeakDetector
from modules.info_disclosure.secret_detector import InfoDisclosureSecretDetector
from modules.info_disclosure.exposure_detector import InfoDisclosureExposureDetector
from modules.info_disclosure.comment_detector import InfoDisclosureCommentDetector

from modules.cookie_security.flag_analyzer import CookieSecurityFlagAnalyzer
from modules.cookie_security.value_analyzer import CookieSecurityValueAnalyzer
from modules.cookie_security.fixation_analyzer import CookieSecuritySessionFixationAnalyzer
from modules.cookie_security.serialization import CookieSecuritySerializationAnalyzer
from modules.cookie_security.injection_via_cookie import CookieSecurityInjectionAnalyzer
from modules.cookie_security.tech_fingerprint import TechFingerprintAnalyzer



class BaseAnalyzer:
    def analyze(self, record: HttpRecord) -> List[Finding]:
        raise NotImplementedError


ALL_ANALYZERS: List[Type[BaseAnalyzer]] = [
    XmlDetector,
    XmlContentTypeAnalyzer,
    XmlSoapDetector,
    LfiFileParamDetector,
    LfiExtensionUrlDetector,
    LfiPatternUrlDetector,
    LfiResponseUrlDetector,
    LfiTraversalHintDetector,
    JwtTokenDetector,
    FileUploadMultipartDetector,
    FileUploadExtensionDetector,
    FileUploadMimeMismatch,
    CacheDetector,
    CsrfTokenDetector,
    CsrfFormAnalyzer,
    CsrfSameSiteAnalyzer,
    CsrfGetStateChangeDetector,
    ClickjackingCspAnalyzer,
    ClickjackingXFrameAnalyzer,
    ClickjackingSameSiteAnalyzer,
    DeserializationSerializedObjectDetector,
    DeserializationViewStateAnalyzer,
    DeserializationTypeHintDetector,
    OauthAuthorizationRequestAnalyzer,
    OauthCallbackAnalyzer,
    OauthTokenEndpointAnalyzer,
    WebsocketHandshakeAnalyzer,
    WebsocketClientCodeAnalyzer,
    InfoDisclosureErrorDetector,
    InfoDisclosureHeaderLeakDetector,
    InfoDisclosureSecretDetector,
    InfoDisclosureExposureDetector,
    InfoDisclosureCommentDetector,
    CookieSecurityFlagAnalyzer,
    CookieSecurityValueAnalyzer,
    CookieSecuritySessionFixationAnalyzer,
    CookieSecuritySerializationAnalyzer,
    CookieSecurityInjectionAnalyzer,
    TechFingerprintAnalyzer,
]

ENABLED_MODULES = {
    "xml", "lfi", "jwt", "file_upload", "cache",
    "csrf", "clickjacking", "deserialization", "oauth", "websocket",
    "info_disclosure", "cookie_security"
}

MODULE_MAP: Dict[str, List[str]] = {
    "xml": ["XmlDetector", "XmlContentTypeAnalyzer", "XmlSoapDetector"],
    "lfi": ["LfiFileParamDetector", "LfiExtensionUrlDetector", "LfiPatternUrlDetector", "LfiResponseUrlDetector", "LfiTraversalHintDetector"],
    "jwt": ["JwtTokenDetector"],
    "file_upload": ["FileUploadMultipartDetector", "FileUploadExtensionDetector", "FileUploadMimeMismatch"],
    "cache": ["CacheDetector"],
    "csrf": ["CsrfTokenDetector", "CsrfFormAnalyzer", "CsrfSameSiteAnalyzer", "CsrfGetStateChangeDetector"],
    "clickjacking": ["ClickjackingCspAnalyzer", "ClickjackingXFrameAnalyzer", "ClickjackingSameSiteAnalyzer"],
    "deserialization": ["DeserializationSerializedObjectDetector", "DeserializationViewStateAnalyzer", "DeserializationTypeHintDetector"],
    "oauth": ["OauthAuthorizationRequestAnalyzer", "OauthCallbackAnalyzer", "OauthTokenEndpointAnalyzer"],
    "websocket": ["WebsocketHandshakeAnalyzer", "WebsocketClientCodeAnalyzer"],
    "info_disclosure": ["InfoDisclosureErrorDetector", "InfoDisclosureHeaderLeakDetector", "InfoDisclosureSecretDetector", "InfoDisclosureExposureDetector", "InfoDisclosureCommentDetector"],
    "cookie_security": ["CookieSecurityFlagAnalyzer", "CookieSecurityValueAnalyzer", "CookieSecuritySessionFixationAnalyzer", "CookieSecuritySerializationAnalyzer", "CookieSecurityInjectionAnalyzer", "TechFingerprintAnalyzer"],
}


class Engine:
    def __init__(self, enabled_modules: set = None):
        active = enabled_modules if enabled_modules else ENABLED_MODULES
        active_classes = set()
        for mod in active:
            active_classes.update(MODULE_MAP.get(mod, []))

        self.analyzers = []
        self.batch_analyzers = []
        self.correlators = []
        for cls in ALL_ANALYZERS:
            if cls.__name__ not in active_classes:
                continue
            instance = cls()
            if hasattr(instance, "correlate"):
                self.correlators.append(instance)
            elif hasattr(instance, "analyze_all"):
                self.batch_analyzers.append(instance)
            else:
                self.analyzers.append(instance)

    def scan(self, records: List[HttpRecord]) -> List[Finding]:
        findings = []
        for index, record in enumerate(records):
            for analyzer in self.analyzers:
                try:
                    results = analyzer.analyze(record)
                    if results:
                        for result in results:
                            if result.extra is None:
                                result.extra = {}
                            result.extra.setdefault("request_index", index)
                        findings.extend(results)
                except Exception:
                    pass

        for batch_analyzer in self.batch_analyzers:
            try:
                results = batch_analyzer.analyze_all(records)
                if results:
                    findings.extend(results)
            except Exception:
                pass

        for correlator in self.correlators:
            try:
                findings = correlator.correlate(records, findings)
            except Exception:
                pass

        # Every request is analysed independently: repeated findings are kept as-is.
        return findings