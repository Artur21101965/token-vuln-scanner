import logging
from src.types import Chain, ContractTarget
from src.rpc import RpcClient

logger = logging.getLogger(__name__)


class StaleContractSource:
    def __init__(self, rpc: RpcClient, min_balance_wei: int = 10 ** 17):
        self._rpc = rpc
        self._min_balance = min_balance_wei

    def check_balance(self, address: str) -> int:
        try:
            raw = self._rpc.eth_get_balance(address)
            return int(raw, 16) if raw else 0
        except Exception as e:
            logger.error("eth_get_balance %s error: %s", address, e)
            return 0
