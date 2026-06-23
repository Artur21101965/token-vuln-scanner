import pytest
from src.db.deployer_store import DeployerStore
from src.types import DeployerInfo


@pytest.fixture
def store(tmp_path):
    s = DeployerStore(db_path=str(tmp_path / "test.db"))
    s.init_db()
    return s


class TestDeployerStore:
    def test_init_db_creates_table(self, store):
        # should not raise
        store.init_db()

    def test_upsert_and_get(self, store):
        store.upsert(DeployerInfo(address="0xabc", chain_name="ethereum", token_count=1, critical_count=0))
        info = store.get("0xabc")
        assert info is not None
        assert info.address == "0xabc"
        assert info.chain_name == "ethereum"
        assert info.token_count == 1

    def test_upsert_increments(self, store):
        store.upsert(DeployerInfo(address="0xabc", chain_name="ethereum", token_count=1, critical_count=0))
        store.upsert(DeployerInfo(address="0xabc", chain_name="ethereum", token_count=2, critical_count=1))
        info = store.get("0xabc")
        assert info.token_count == 2
        assert info.critical_count == 1

    def test_get_returns_none_for_unknown(self, store):
        assert store.get("0xnonexistent") is None

    def test_add_token_record_creates_deployer(self, store):
        store.add_token("0xabc", "ethereum", has_critical=False)
        info = store.get("0xabc")
        assert info is not None
        assert info.token_count == 1
        assert info.critical_count == 0

    def test_add_token_record_increments(self, store):
        store.add_token("0xabc", "ethereum", has_critical=False)
        store.add_token("0xabc", "ethereum", has_critical=True)
        info = store.get("0xabc")
        assert info.token_count == 2
        assert info.critical_count == 1

    def test_token_count_across_chains(self, store):
        store.add_token("0xabc", "ethereum", has_critical=False)
        store.add_token("0xabc", "bsc", has_critical=True)
        info = store.get("0xabc")
        assert info.token_count == 2
        assert info.critical_count == 1

    def test_is_known_scammer_returns_true_for_high_critical(self, store):
        store.add_token("0xabc", "ethereum", has_critical=True)
        store.add_token("0xabc", "ethereum", has_critical=True)
        store.add_token("0xabc", "ethereum", has_critical=True)
        assert store.is_known_scammer("0xabc") is True

    def test_is_known_scammer_returns_false_for_few_critical(self, store):
        store.add_token("0xabc", "ethereum", has_critical=True)
        store.add_token("0xabc", "ethereum", has_critical=False)
        assert store.is_known_scammer("0xabc") is False

    def test_is_known_scammer_returns_false_for_unknown(self, store):
        assert store.is_known_scammer("0xnonexistent") is False

    def test_deployer_info_defaults(self):
        info = DeployerInfo(address="0xabc")
        assert info.token_count == 0
        assert info.critical_count == 0
        assert info.chain_name == ""
