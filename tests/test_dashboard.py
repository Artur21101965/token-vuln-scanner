from pathlib import Path
from unittest.mock import patch
from src.web.dashboard import app
from fastapi.testclient import TestClient

client = TestClient(app)

FAKE_REPORT = {
    "token": {"symbol": "TST", "address": "0xabc"},
    "pool": {"address": "0xpool", "dex": "Uniswap"},
    "scanned_at": "2026-06-16T12:00:00",
    "findings": [
        {"check_name": "test_check", "severity": "HIGH", "description": "Test finding", "recommendation": "Fix it"},
    ],
}


def _fake_loader(base_dir: str) -> list[dict]:
    r = dict(FAKE_REPORT)
    r["_chain"] = "ethereum"
    r["_file"] = "/fake/report.json"
    r["_token_address"] = "0xabc"
    r["_scanned_at"] = "2026-06-16T12:00:00"
    r["_token_symbol"] = "TST"
    return [r]


class TestDashboard:
    def test_index_returns_200(self):
        with patch("src.web.dashboard._load_all_reports", return_value=_fake_loader("")):
            resp = client.get("/")
            assert resp.status_code == 200
            assert "Vuln Scanner" in resp.text

    def test_index_shows_severity_counts(self):
        with patch("src.web.dashboard._load_all_reports", return_value=_fake_loader("")):
            resp = client.get("/")
            assert resp.status_code == 200
            assert "HIGH" in resp.text

    def test_token_detail_returns_200(self):
        with patch("src.web.dashboard._load_all_reports", return_value=_fake_loader("")):
            resp = client.get("/token/0xabc")
            assert resp.status_code == 200
            assert "Test finding" in resp.text

    def test_token_detail_404(self):
        with patch("src.web.dashboard._load_all_reports", return_value=_fake_loader("")):
            resp = client.get("/token/0xdead")
            assert resp.status_code == 404

    def test_search_returns_results(self):
        with patch("src.web.dashboard._load_all_reports", return_value=_fake_loader("")):
            resp = client.get("/search?q=TST")
            assert resp.status_code == 200
            assert "TST" in resp.text

    def test_search_empty_query(self):
        resp = client.get("/search?q=")
        assert resp.status_code == 200
        assert resp.text == ""

    def test_recent_findings(self):
        with patch("src.web.dashboard._load_all_reports", return_value=_fake_loader("")):
            resp = client.get("/stats/recent-findings")
            assert resp.status_code == 200
            assert "Test finding" in resp.text
