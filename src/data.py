from typing import Optional, Callable
from src.types import Chain
from src.rpc import RpcClient
from src.explorer import ExplorerClient


class DataCollector:
    def __init__(self, rpc: RpcClient, explorer: ExplorerClient):
        self._rpc = rpc
        self._explorer = explorer
        self._cache: dict[str, str] = {}

    def _cached(self, key: str, fetcher: Callable[[], str]) -> str:
        if key not in self._cache:
            self._cache[key] = fetcher()
        return self._cache[key]

    def _cached_opt(self, key: str, fetcher: Callable[[], Optional[str]]) -> Optional[str]:
        if key not in self._cache:
            result = fetcher()
            self._cache[key] = result if result is not None else ""
        val = self._cache[key]
        return val if val else None

    def clear_cache(self):
        self._cache.clear()

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> str:
        return self._rpc.get_storage_at(address, slot, block)

    def call_contract(self, to: str, data: str, chain: Chain, block: str = "latest") -> str:
        return self._rpc.eth_call(to, data, block)

    def get_code(self, address: str, block: str = "latest") -> str:
        return self._cached(f"code:{address}:{block}",
            lambda: self._rpc.eth_get_code(address, block))

    def get_abi(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._cached_opt(f"abi:{address}:{chain.value}",
            lambda: self._explorer.get_abi(address, chain))

    def get_source_code(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._explorer.get_source_code(address, chain)

    def get_creator_address(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._explorer.get_contract_creation(address, chain)

    def is_verified(self, address: str, chain: Chain) -> bool:
        return self.get_abi(address, chain) is not None

    def get_total_supply(self, address: str, block: str = "latest") -> int:
        selector = "0x18160ddd"
        raw = self._rpc.eth_call(address, selector, block)
        return int(raw, 16) if raw and len(raw) > 2 else 0

    def get_balance_of(self, address: str, wallet: str, block: str = "latest") -> int:
        padded = wallet.lower().replace("0x", "").zfill(64)
        selector = "0x70a08231" + padded
        raw = self._rpc.eth_call(address, selector, block)
        return int(raw, 16) if raw and len(raw) > 2 else 0

    def get_name(self, address: str) -> str:
        selector = "0x06fdde03"
        raw = self._rpc.eth_call(address, selector)
        if not raw or len(raw) < 2:
            return ""
        try:
            hex_str = raw[2:]
            offset = int(hex_str[:64], 16) * 2 + 64
            length = int(hex_str[64:128], 16) * 2
            raw_name = bytes.fromhex(hex_str[offset:offset + length])
            return raw_name.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def fallback_detected(self, address: str) -> bool:
        try:
            data = "0xdeadbeef" + "0" * 64
            self._rpc.eth_call(address, data)
            return True
        except Exception:
            return False

    def get_decimals(self, address: str) -> int:
        selector = "0x313ce567"
        raw = self._rpc.eth_call(address, selector)
        try:
            return int(raw, 16) if raw else 18
        except Exception:
            return 18
