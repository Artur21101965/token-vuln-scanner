import pytest
from unittest.mock import Mock
from src.scanners.solana_scanner import SolanaScanner
from src.data import DataCollector
from src.rpc import RpcClient


def test_solana_scanner_creates():
    scanner = SolanaScanner(data_collector=Mock(), rpc=Mock())
    assert len(scanner.checks) == 3
    assert all(c.name for c in scanner.checks)
