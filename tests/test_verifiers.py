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
    assert r.confirmed is True
    assert r.confidence < 1.0


def test_honeypot_verifier_sell_possible():
    rpc = Mock(spec=RpcClient)
    abi_encoded = (
        "0x"
        "0000000000000000000000000000000000000000000000000000000000000020"  # offset
        "0000000000000000000000000000000000000000000000000000000000000003"  # length=3
        "00000000000000000000000000000000000000000000000000000002540be400"  # 10 ETH in
        "0000000000000000000000000000000000000000000000000000000000000064"  # 100 tokens bought
        "0000000000000000000000000000000000000000000000000000000000000032"  # 50 wei from sell
    )
    rpc.eth_call.return_value = abi_encoded
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
    assert r.confidence > 0  # false positive — sell works


def test_honeypot_verifier_sell_reverts():
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
    assert r.confirmed is True  # confirmed as honeypot
    assert r.confidence > 0.5


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
    # ABI-encoded return with sell_amount > 0
    abi_encoded = (
        "0x"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "0000000000000000000000000000000000000000000000000000000000000003"
        "00000000000000000000000000000000000000000000000000000002540be400"
        "0000000000000000000000000000000000000000000000000000000000000064"
        "0000000000000000000000000000000000000000000000000000000000000032"
    )
    rpc.eth_call.return_value = abi_encoded
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
    assert "false positive" in result[0].description.lower()
