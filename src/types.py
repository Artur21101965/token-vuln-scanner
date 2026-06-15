from __future__ import annotations
from decimal import Decimal
from enum import IntEnum, StrEnum, auto
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class Chain(IntEnum):
    ETHEREUM = auto()
    BSC = auto()
    SOLANA = auto()

    @classmethod
    def from_str(cls, s: str) -> "Chain":
        mapping = {
            "ethereum": cls.ETHEREUM,
            "bsc": cls.BSC,
            "solana": cls.SOLANA,
        }
        try:
            return mapping[s.lower()]
        except KeyError:
            raise ValueError(f"Unknown chain: {s}. Valid options: {', '.join(mapping.keys())}")


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class TokenStatus(StrEnum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"


@dataclass
class TokenInfo:
    address: str
    symbol: str
    chain: Chain
    name: str = ""
    decimals: int = 18


@dataclass
class PoolInfo:
    address: str
    dex: str
    liquidity_usd: Decimal
    token0_address: str = ""
    token1_address: str = ""


@dataclass
class Finding:
    check_name: str
    severity: Severity
    description: str
    recommendation: str
    details: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    token: TokenInfo
    pool: PoolInfo
    findings: list[Finding]
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def summary(self) -> str:
        if not self.findings:
            return "✅ No vulnerabilities found"
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.name] = by_sev.get(f.severity.name, 0) + 1
        parts = [f"{sev}={cnt}" for sev, cnt in sorted(by_sev.items(), reverse=True)]
        return f"{'⚠️'} {', '.join(parts)}"


@dataclass
class PendingToken:
    row_id: int = 0
    chain: Chain = Chain.ETHEREUM
    token_address: str = ""
    pair_address: str = ""
    symbol: str = ""
    liquidity_usd: Decimal = Decimal("0.0")
    dex: str = ""
    status: TokenStatus = TokenStatus.PENDING
    error: str = ""
