from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Request:
    method: str
    url: str
    headers: dict
    params: dict
    body: Optional[str]
    content_type: Optional[str]
    raw: Optional[str] = None


@dataclass
class Response:
    status: int
    headers: dict
    body: Optional[str]
    content_type: Optional[str]


@dataclass
class HttpRecord:
    request: Request
    response: Response
    source_file: Optional[str] = None


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    location: str
    evidence: str
    vector_hint: Optional[str] = None
    confidence: str = "candidate"
    extra: dict = field(default_factory=dict)