from typing import Any
from src.verifiers.base import Verifier, VerificationResult
from src.types import Finding, Severity
from src.scanners.base import CheckContext
from src.wallet import load_wallet_addresses

ATTACK_CHAINS: list[dict[str, Any]] = [
    {
        "name": "ownership_takeover",
        "steps": ["public_ownership_transfer", "unprotected_upgrade"],
        "description": "Transfer ownership then upgrade implementation to malicious contract",
        "critical": True,
    },
    {
        "name": "initialize_and_mint",
        "steps": ["unprotected_initialize", "unprotected_mint"],
        "description": "Re-initialize contract then mint unlimited tokens",
        "critical": True,
    },
    {
        "name": "full_drain",
        "steps": ["public_ownership_transfer", "unprotected_withdraw"],
        "description": "Take ownership then withdraw all ETH from contract",
        "critical": True,
    },
    {
        "name": "mint_and_withdraw",
        "steps": ["unprotected_mint", "unprotected_withdraw"],
        "description": "Mint unlimited tokens then drain ETH",
        "critical": True,
    },
    {
        "name": "ownership_and_initialize",
        "steps": ["public_ownership_transfer", "unprotected_initialize"],
        "description": "Take ownership then re-initialize contract parameters",
        "critical": False,
    },
]

DUMMY_ADDR = "0x0000000000000000000000000000000000000002"
ATTACKER = "0x0000000000000000000000000000000000000003"

SELECTOR_CALLDATA: dict[str, str] = {
    "8129fc1c": "8129fc1c",
    "f2fde38b": "f2fde38b" + DUMMY_ADDR[2:].zfill(64),
    "3659cfe6": "3659cfe6" + DUMMY_ADDR[2:].zfill(64),
    "40c10f19": "40c10f19" + ATTACKER[2:].zfill(64) + "0" * 64,
    "2e1a7d4d": "2e1a7d4d" + "0" * 64,
}


class MultiStepVerifier(Verifier):
    def __init__(self):
        self._wallets = load_wallet_addresses()

    @property
    def name(self) -> str:
        return "multi_step"

    def can_verify(self, finding: Finding) -> bool:
        return False  # This verifier is not called per-finding

    def verify(self, ctx: CheckContext, finding: Finding) -> VerificationResult:
        raise NotImplementedError("MultiStepVerifier uses verify_chain()")

    def verify_chain(self, ctx: CheckContext, findings: list[Finding]) -> list[Finding]:
        check_names = {f.check_name for f in findings if f.severity >= Severity.HIGH}
        attacker = self._attacker(ctx)

        for chain in ATTACK_CHAINS:
            if not all(step in check_names for step in chain["steps"]):
                continue

            evidence = self._test_chain(ctx, chain, findings, attacker)
            if evidence is None:
                continue

            for finding in findings:
                if "multi_step_chains" not in finding.details:
                    finding.details["multi_step_chains"] = []
                finding.details["multi_step_chains"].append({
                    "chain": chain["name"],
                    "description": chain["description"],
                    "evidence": evidence,
                    "critical": chain["critical"],
                })
        return findings

    def _attacker(self, ctx: CheckContext) -> str:
        return self._wallets.get(ctx.token.chain, ATTACKER)

    def _test_chain(
        self, ctx: CheckContext, chain: dict[str, Any],
        findings: list[Finding], attacker: str,
    ) -> str | None:
        step_results: list[str] = []
        for step_name in chain["steps"]:
            finding = next((f for f in findings if f.check_name == step_name), None)
            if finding is None:
                return None
            selector = finding.details.get("selector", "")
            calldata_str = SELECTOR_CALLDATA.get(selector, "")
            if not calldata_str:
                step_results.append(f"{step_name}: no calldata")
                continue
            try:
                ctx.rpc.eth_call(ctx.token.address, "0x" + calldata_str, from_address=attacker)
                step_results.append(f"{step_name}: OK")
            except Exception as e:
                step_results.append(f"{step_name}: REVERTED ({e})")
                return None
        return "; ".join(step_results)
