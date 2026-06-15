from __future__ import annotations
from enum import IntEnum, auto
from dataclasses import dataclass, field
from datetime import datetime
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
        return mapping[s.lower()]


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


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
    liquidity_usd: float
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
class CheckResult:
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
    scanned_at: datetime = field(default_factory=datetime.utcnow)

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
    id: int = 0
    chain: Chain = Chain.ETHEREUM
    token_address: str = ""
    pair_address: str = ""
    symbol: str = ""
    liquidity_usd: float = 0.0
    dex: str = ""
    status: str = "pending"  # pending | analyzing | done | failed
