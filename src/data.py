from typing import Optional
from src.types import Chain
from src.rpc import RpcClient
from src.explorer import ExplorerClient


class DataCollector:
    def __init__(self, rpc: RpcClient, explorer: ExplorerClient):
        self._rpc = rpc
        self._explorer = explorer

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> str:
        return self._rpc.get_storage_at(address, slot, block)

    def call_contract(self, to: str, data: str, chain: Chain, block: str = "latest") -> str:
        return self._rpc.eth_call(to, data, block)

    def get_code(self, address: str, block: str = "latest") -> str:
        return self._rpc.eth_get_code(address, block)

    def get_abi(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._explorer.get_abi(address, chain)

    def get_source_code(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        return self._explorer.get_source_code(address, chain)
