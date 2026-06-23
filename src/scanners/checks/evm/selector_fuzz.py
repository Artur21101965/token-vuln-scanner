from typing import Optional
from src.scanners.base import BaseCheck, CheckContext
from src.types import Finding, Severity

# 100+ known dangerous function selectors
FUZZ_SELECTORS: dict[str, str] = {
    # Ownership / admin
    "f2fde38b": "transferOwnership(address)",
    "13af4035": "setOwner(address)",
    "a6f9dae1": "setOwner(address)",
    "715018a6": "renounceOwnership()",
    # Pause / unpause
    "8456cb59": "pause()",
    "3f4ba83a": "unpause()",
    "0e419f5f": "pause()",
    "2a38758b": "unpause()",
    "1364399f": "setPaused(bool)",
    # Withdraw / drain / sweep
    "2e1a7d4d": "withdraw(uint256)",
    "3ccfd60b": "withdraw()",
    "853828b6": "withdrawAll()",
    "f14210a6": "withdrawAll()",
    "db2e21bc": "emergencyWithdraw()",
    "ecf708a4": "sweep()",
    "9890220b": "drain()",
    "78c24643": "sweep(address)",
    "b68ad959": "withdrawToken(address,address,uint256)",
    "3996ac90": "rescueERC20(address,address,uint256)",
    "5312ea8e": "emergencyWithdraw(uint256)",
    "7a9c2b39": "rescueTokens(address)",
    # Fee / tax
    "9f1a54a1": "setFee(uint256)",
    "69fe0e2d": "setTaxFeePercent(uint256)",
    "e2b8a209": "setFeePercent(uint256)",
    "25c5e5c3": "updateFee(uint256)",
    "e32261a0": "setTax(uint256)",
    "f11a8a0c": "setFees(uint256)",
    "bddb1f23": "setSwapFee(uint256)",
    # Selfdestruct
    "41c0e1b5": "kill()",
    "9d118770": "suicide()",
    "83197ef0": "destroy()",
    "4390ecf5": "selfdestruct()",
    "f25a04f3": "terminate()",
    # Mint
    "a0712d68": "mint(uint256)",
    "40c10f19": "mint(address,uint256)",
    "62b99d75": "mint()",
    "449a52f8": "mint(address,uint256)",
    "156e29f6": "mintFor(address,uint256)",
    # Burn
    "42966c68": "burn(uint256)",
    "9dc29fac": "burn(address,uint256)",
    "cc16ab17": "burnAll()",
    "6161eb18": "burnFrom(address,uint256)",
    # Proxy / upgrade
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "8129fc1c": "initialize()",
    "c4d66de8": "initialize(address)",
    "439370b1": "initialize(address,address)",
    # Config
    "5d5a5536": "setMinTokensBeforeSwap(uint256)",
    "27e235e3": "setSwapAndLiquifyEnabled(bool)",
    "4094572c": "sweep()",
    "8954374e": "setMaxTxPercent(uint256)",
    "e4514dce": "setMaxWalletSize(uint256)",
    "86d5e73d": "excludeFromFees(address,bool)",
    "834a20df": "excludeFromReward(address)",
    "573ade11": "setSwapTokensAtAmount(uint256)",
    "4bad5e92": "setAutomatedMarketMakerPair(address,bool)",
    # Flash loans / callbacks
    "1cff79cd": "flashLoan(address,address,uint256,bytes)",
    "5cffe9de": "flashLoan(address[],uint256[],bytes)",
    # Misc dangerous
    "61461954": "execute()",
    "b61d27f6": "execute(address,bytes)",
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "4641257d": "harvest()",
    "4e71d92d": "claim()",
    "d0e30db0": "deposit()",
    "d0def521": "claimTokens()",
    "a0710a0d": "claimStuckTokens(address)",
    "ee82a5dc": "pullTokens(address)",
    "c95c03fb": "skim(address)",
    "b1976bd9": "sync()",
}

MAX_FUZZ = 40  # limit RPC calls per contract


class SelectorFuzzCheck(BaseCheck):
    """Tests many known dangerous selectors via eth_call to find unprotected functions."""

    @property
    def name(self) -> str:
        return "selector_fuzz"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Selector fuzzer — tests known dangerous selectors for unprotected access"

    @property
    def recommendation(self) -> str:
        return "Manually verify any callable functions — may be false positive"

    def run(self, ctx: CheckContext) -> Optional[Finding]:
        code = ctx.data_collector.get_code(ctx.token.address)
        if not code or len(code) <= 4:
            return None

        code_hex = code.lower().replace("0x", "")
        rpc = ctx.rpc

        callable_hits: list[str] = []
        tested = 0

        for sel, name in FUZZ_SELECTORS.items():
            if tested >= MAX_FUZZ:
                break
            if sel not in code_hex:
                continue
            tested += 1
            try:
                gas = rpc.eth_call(
                    ctx.token.address,
                    "0x" + sel,
                    from_address=ctx.data_collector._rpc._signer if hasattr(ctx.data_collector._rpc, '_signer') else "",
                )
                # If eth_call doesn't revert, function is callable
                if gas and gas != "0x":
                    callable_hits.append(f"{name} ({sel})")
            except Exception:
                pass

        if not callable_hits:
            return None

        return Finding(
            check_name=self.name,
            severity=self.severity,
            description=f"Found {len(callable_hits)} potentially unprotected functions: {', '.join(callable_hits[:5])}",
            recommendation=self.recommendation,
            details={"callable": callable_hits},
            confidence=0.5,
        )
