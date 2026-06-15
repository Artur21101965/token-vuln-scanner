import pytest
import json
import tempfile
import os
from decimal import Decimal
from datetime import datetime, timezone
from src.reporter.json_report import JsonReporter
from src.types import TokenInfo, PoolInfo, Finding, Severity, Chain, ScanReport


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    import shutil
    shutil.rmtree(d)


@pytest.fixture
def sample_report():
    return ScanReport(
        token=TokenInfo(address="0xabc123", symbol="TEST", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap V2", liquidity_usd=Decimal("5000")),
        findings=[
            Finding(check_name="mint", severity=Severity.CRITICAL, description="Mint not restricted", recommendation="Fix mint"),
            Finding(check_name="owner", severity=Severity.HIGH, description="Owner not renounced", recommendation="Renounce"),
        ],
        scanned_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_report_writes_json(temp_dir, sample_report):
    reporter = JsonReporter(output_dir=temp_dir)
    path = reporter.write(sample_report)
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data["token"]["address"] == "0xabc123"
    assert data["token"]["symbol"] == "TEST"
    assert data["token"]["chain"] == "ethereum"
    assert data["pool"]["dex"] == "Uniswap V2"
    assert data["pool"]["liquidity_usd"] == 5000.0
    assert len(data["findings"]) == 2
    assert data["findings"][0]["check_name"] == "mint"
    assert data["findings"][0]["severity"] == "CRITICAL"


def test_report_creates_text_summary(temp_dir, sample_report):
    reporter = JsonReporter(output_dir=temp_dir)
    path = reporter.write(sample_report)
    txt_path = path.replace(".json", ".txt")
    assert os.path.exists(txt_path)
    with open(txt_path) as f:
        content = f.read()
    assert "TEST" in content
    assert "CRITICAL" in content
    assert "Mint not restricted" in content


def test_report_empty_findings(temp_dir):
    report = ScanReport(
        token=TokenInfo(address="0xabc", symbol="SAFE", chain=Chain.ETHEREUM),
        pool=PoolInfo(address="0xpool", dex="Uniswap", liquidity_usd=Decimal("1000")),
        findings=[],
    )
    reporter = JsonReporter(output_dir=temp_dir)
    path = reporter.write(report)
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert len(data["findings"]) == 0
    assert "No vulnerabilities" in data["summary"]


def test_report_chain_directory(temp_dir, sample_report):
    reporter = JsonReporter(output_dir=temp_dir)
    path = reporter.write(sample_report)
    assert "ethereum" in path
    assert "0xabc123" in path
