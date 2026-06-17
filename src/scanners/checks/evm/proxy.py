from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity, TokenInfo, Chain

IMPLEMENTATION_SLOTS = [
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # EIP-1967
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",  # EIP-1967 beacon
    "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",  # EIP-1822 (UUPS)
]


class ProxyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "upgradeable_proxy"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Contract uses delegatecall — may be upgradeable proxy"

    @property
    def recommendation(self) -> str:
        return "Ensure proxy admin is renounced or timelocked"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or "delegatecall" not in code.lower():
            return None

        impl = self._get_implementation(ctx)
        finding = Finding(
            check_name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
        )
        if impl:
            finding.details["implementation"] = impl
            impl_findings = self._scan_implementation(ctx, impl)
            if impl_findings:
                finding.details["impl_findings"] = impl_findings
                finding.description += f" — impl {impl[:10]}... has {len(impl_findings)} findings"

        return finding

    def _get_implementation(self, ctx: CheckContext) -> Optional[str]:
        dc = ctx.data_collector
        for slot in IMPLEMENTATION_SLOTS:
            try:
                raw = dc.get_storage_at(ctx.token.address, int(slot, 16))
                addr = "0x" + raw[26:] if len(raw) >= 66 else raw
                if addr and int(addr, 16) != 0:
                    return addr
            except Exception:
                continue
        return None

    def _scan_implementation(self, ctx: CheckContext, impl: str) -> list[str]:
        """Scan implementation contract for unprotected init and selfdestruct."""
        findings = []
        from src.scanners.checks.evm.hidden import HiddenSelfdestructCheck
        from src.scanners.checks.evm.initialize import InitializeCheck
        from src.scanners.checks.evm.ownership_transfer import OwnershipTransferCheck

        check_ctx = CheckContext(
            token=TokenInfo(address=impl, symbol=ctx.token.symbol, chain=ctx.token.chain),
            pool=ctx.pool,
            data_collector=ctx.data_collector,
            rpc=ctx.rpc,
        )

        sd = HiddenSelfdestructCheck().run(check_ctx)
        if sd:
            findings.append("selfdestruct_in_impl")

        init = InitializeCheck().run(check_ctx)
        if init:
            findings.append("unprotected_initialize_in_impl")

        own = OwnershipTransferCheck().run(check_ctx)
        if own:
            findings.append("public_ownership_in_impl")

        return findings
