from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..data import get_check_metadata


@dataclass
class Finding:
    check_id: str
    resource: str
    evidence: str

    notes: Optional[str] = None
    is_error: bool = False
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    title: Optional[str] = field(default=None, init=False)
    severity: Optional[str] = field(default=None, init=False)
    category: Optional[str] = field(default=None, init=False)
    description: Optional[str] = field(default=None, init=False)
    risk: Optional[str] = field(default=None, init=False)
    remediation: Optional[str] = field(default=None, init=False)
    reference_url: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        if self.check_id.startswith(("org-", "repo-")):
            metadata = get_check_metadata(self.check_id)
            if metadata:
                self.title = metadata["title"]
                self.severity = metadata["severity"]
                self.category = metadata["category"]
                self.description = metadata["description"]
                self.risk = metadata["risk"]
                self.remediation = metadata["remediation"]
                self.reference_url = metadata.get("reference_url", "")

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "resource": self.resource,
            "evidence": self.evidence,
            "description": self.description,
            "risk": self.risk,
            "remediation": self.remediation,
            "reference_url": self.reference_url,
            "notes": self.notes,
            "timestamp": self.timestamp,
        }


@dataclass
class DependencyFinding:
    repository: str
    package: str
    version: str
    ecosystem: str
    file_path: str
    severity: str
    advisory_id: str
    title: str
    cvss_score: str
    url: str

    def to_dict(self) -> dict:
        return {
            "type": "dependency",
            "repository": self.repository,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "file_path": self.file_path,
            "severity": self.severity,
            "advisory_id": self.advisory_id,
            "title": self.title,
            "cvss_score": self.cvss_score,
            "url": self.url,
        }


@dataclass
class SecretFinding:
    repository: str
    file_path: str
    secret_type: str
    line_number: Optional[int] = None
    secret_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "type": "secret",
            "repository": self.repository,
            "file_path": self.file_path,
            "secret_type": self.secret_type,
            "line_number": self.line_number,
            "secret_hash": self.secret_hash,
        }
