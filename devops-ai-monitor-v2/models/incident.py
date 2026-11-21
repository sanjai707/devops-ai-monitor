from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class Incident:
    id: int
    fingerprint: str
    container_id: str
    container_name: str
    type: str
    severity: str
    title: str
    status: str
    evidence: dict
    created_at: str
    updated_at: str
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None

    def to_dict(self):
        return asdict(self)
