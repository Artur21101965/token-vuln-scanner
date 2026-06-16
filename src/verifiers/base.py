from abc import ABC, abstractmethod
from dataclasses import dataclass
from src.types import Finding
from src.scanners.base import CheckContext


@dataclass
class VerificationResult:
    finding: Finding
    confirmed: bool
    confidence: float
    evidence: str


class Verifier(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def can_verify(self, finding: Finding) -> bool:
        ...

    @abstractmethod
    def verify(self, ctx: CheckContext, finding: Finding) -> VerificationResult:
        ...
