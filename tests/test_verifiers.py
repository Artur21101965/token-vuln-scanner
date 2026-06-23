import pytest
from unittest.mock import Mock, patch
from src.types import Finding, Severity, TokenInfo, PoolInfo, Chain
from src.scanners.base import CheckContext
from src.verifiers.base import Verifier, VerificationResult
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.runner import VerifierRunner
from src.data import DataCollector
from src.rpc import RpcClient


def test_verifier_interface():
    class TestVerifier(Verifier):
        @property
        def name(self) -> str: return "test"
        def can_verify(self, finding: Finding) -> bool:
            return finding.check_name == "testable"
        def verify(self, ctx: CheckContext, finding: Finding) -> VerificationResult:
            return VerificationResult(finding=finding, confirmed=True, confidence=1.0, evidence="ok")

    v = TestVerifier()
    assert v.can_verify(Finding(check_name="testable", severity=Severity.LOW, description="", recommendation=""))
    assert not v.can_verify(Finding(check_name="other", severity=Severity.LOW, description="", recommendation=""))


def test_verification_result():
    f = Finding(check_name="x", severity=Severity.HIGH, description="test", recommendation="fix")
    r = VerificationResult(finding=f, confirmed=True, confidence=0.95, evidence="on-chain check passed")
    assert r.confirmed is True
    assert r.confidence == 0.95
    assert "on-chain" in r.evidence


def test_honeypot_verifier_can_verify():
    v = HoneypotVerifier()
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    assert v.can_verify(f)
    assert not v.can_verify(Finding(check_name="owner_not_renounced", severity=Severity.HIGH, description="", recommendation=""))


def test_honeypot_verifier_no_pair_address():
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="", dex="Uniswap", liquidity_usd=5000),  # empty pair
        data_collector=Mock(spec=DataCollector),
        rpc=Mock(spec=RpcClient),
    )
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    v = HoneypotVerifier()
    r = v.verify(ctx, f)
    assert r.confirmed is False
    assert r.confidence < 1.0


# swapExactETHForTokens returns: [0.1 ETH in, 10^18 tokens out] → ~0% buy tax
# ABI-encoded: offset(32) | length=2(32) | amounts[0](32) | amounts[1](32)
BUY_RESULT_OK = (
    "0x"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "000000000000000000000000000000000000000000000000016345785d8a0000"
    "0000000000000000000000000000000000000000000000008ac7230489e80000"
)


def test_honeypot_verifier_buy_ok_low_tax():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.return_value = BUY_RESULT_OK
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    v = HoneypotVerifier()
    r = v.verify(ctx, f)
    assert r.confirmed is False
    assert r.confidence > 0


def test_honeypot_verifier_buy_reverts():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.side_effect = RuntimeError("execution reverted")
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    v = HoneypotVerifier()
    r = v.verify(ctx, f)
    assert r.confirmed is True
    assert r.confidence > 0.9


def test_honeypot_verifier_bsc():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.return_value = BUY_RESULT_OK
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.BSC),
        pool=PoolInfo(address="0xpool", dex="PancakeSwap", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    v = HoneypotVerifier()
    r = v.verify(ctx, f)
    assert r.confirmed is False
    assert "BSC" in r.evidence


def test_honeypot_verifier_polygon():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.side_effect = RuntimeError("reverted")
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.POLYGON),
        pool=PoolInfo(address="0xpool", dex="QuickSwap", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    v = HoneypotVerifier()
    r = v.verify(ctx, f)
    assert r.confirmed is True
    assert "POLYGON" in r.evidence


def test_honeypot_verifier_unsupported_chain():
    rpc = Mock(spec=RpcClient)
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.SOLANA),
        pool=PoolInfo(address="0xpool", dex="Raydium", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    f = Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="", recommendation="")
    v = HoneypotVerifier()
    r = v.verify(ctx, f)
    assert r.confirmed is False
    assert r.confidence == 0.0


def test_verifier_runner_runs_applicable():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.side_effect = RuntimeError("reverted")
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    findings = [
        Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="Flagged", recommendation=""),
        Finding(check_name="owner_not_renounced", severity=Severity.HIGH, description="Owner not zero", recommendation=""),
    ]
    runner = VerifierRunner(verifiers=[HoneypotVerifier()])
    result = runner.verify_findings(ctx, findings)
    assert len(result) == 2
    assert "verified" in result[0].details  # honeypot was verified
    assert "verified" not in result[1].details  # owner was not
    assert result[0].details["verified"] is True  # confirmed as honeypot


def test_verifier_runner_dismisses_false_positive():
    rpc = Mock(spec=RpcClient)
    rpc.eth_call.side_effect = [BUY_RESULT_OK, "0x01"]
    ctx = CheckContext(
        token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=5000),
        data_collector=Mock(spec=DataCollector),
        rpc=rpc,
    )
    findings = [
        Finding(check_name="potential_honeypot", severity=Severity.CRITICAL, description="Flagged", recommendation=""),
    ]
    runner = VerifierRunner(verifiers=[HoneypotVerifier()])
    result = runner.verify_findings(ctx, findings)
    assert result[0].details["verified"] is False  # false positive
    assert "dismissed" in result[0].description.lower()


# ── Multi-step verifier tests ──────────────────────────────────────────────────

def _chain_finding(check_name: str, selector: str, severity=Severity.CRITICAL) -> Finding:
    return Finding(
        check_name=check_name, severity=severity,
        description=check_name, recommendation="fix it",
        details={"selector": selector},
    )


class TestMultiStepVerifier:
    def test_name(self):
        from src.verifiers.multi_step import MultiStepVerifier
        v = MultiStepVerifier()
        assert v.name == "multi_step"

    def test_can_verify_returns_false(self):
        from src.verifiers.multi_step import MultiStepVerifier
        v = MultiStepVerifier()
        assert v.can_verify(_chain_finding("test", "f2fde38b")) is False

    def test_no_matching_chain_returns_no_change(self):
        from src.verifiers.multi_step import MultiStepVerifier
        rpc = Mock(spec=RpcClient)
        ctx = CheckContext(token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
                           pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
                           data_collector=Mock(spec=DataCollector), rpc=rpc)
        findings = [_chain_finding("some_unknown_check", "8129fc1c")]
        result = MultiStepVerifier().verify_chain(ctx, findings)
        assert len(result) == 1
        assert "multi_step_chains" not in result[0].details

    def test_ownership_takeover_chain_detected(self):
        from src.verifiers.multi_step import MultiStepVerifier
        rpc = Mock(spec=RpcClient)
        rpc.eth_call.return_value = "0x"
        ctx = CheckContext(token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
                           pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
                           data_collector=Mock(spec=DataCollector), rpc=rpc)
        findings = [_chain_finding("public_ownership_transfer", "f2fde38b"),
                    _chain_finding("unprotected_upgrade", "3659cfe6")]
        result = MultiStepVerifier().verify_chain(ctx, findings)
        chains = result[0].details.get("multi_step_chains", [])
        assert any(c["chain"] == "ownership_takeover" for c in chains)

    def test_missing_step_no_chain(self):
        from src.verifiers.multi_step import MultiStepVerifier
        rpc = Mock(spec=RpcClient)
        ctx = CheckContext(token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
                           pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
                           data_collector=Mock(spec=DataCollector), rpc=rpc)
        findings = [_chain_finding("public_ownership_transfer", "f2fde38b")]
        result = MultiStepVerifier().verify_chain(ctx, findings)
        assert "multi_step_chains" not in result[0].details

    def test_chain_via_runner(self):
        from src.verifiers.multi_step import MultiStepVerifier
        rpc = Mock(spec=RpcClient)
        rpc.eth_call.return_value = "0x"
        ctx = CheckContext(token=TokenInfo(address="0xabc", symbol="T", chain=Chain.ETHEREUM),
                           pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=5000),
                           data_collector=Mock(spec=DataCollector), rpc=rpc)
        findings = [_chain_finding("unprotected_mint", "40c10f19"),
                    _chain_finding("unprotected_withdraw", "2e1a7d4d")]
        runner = VerifierRunner(verifiers=[MultiStepVerifier()])
        result = runner.verify_findings(ctx, findings)
        assert "multi_step_chains" in result[0].details
