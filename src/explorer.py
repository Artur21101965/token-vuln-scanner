"""Explorer API client — Etherscan V2 family (Etherscan, Arbiscan, Basescan, etc)."""
from typing import Optional
import httpx
from src.types import Chain


CHAIN_IDS = {
    Chain.ETHEREUM: 1,
    Chain.BSC: 56,
    Chain.ARBITRUM: 42161,
    Chain.BASE: 8453,
    Chain.POLYGON: 137,
    Chain.AVALANCHE: 43114,
    Chain.OPTIMISM: 10,
    Chain.ZKSYNC: 324,
    Chain.LINEA: 59144,
    Chain.SCROLL: 534352,
}


class ExplorerClient:
    def __init__(self, api_key: str = ""):
        self._key = api_key
        self._http = httpx.Client(timeout=15, follow_redirects=True)

    @staticmethod
    def _base_url() -> str:
        return "https://api.etherscan.io/v2/api"

    def _params(self, address: str, action: str, chain: Chain) -> dict:
        return {
            "chainId": CHAIN_IDS.get(chain, 1),
            "module": "contract",
            "action": action,
            "address": address,
            "apikey": self._key,
        }

    def get_abi(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        chain_id = CHAIN_IDS.get(chain)
        if not chain_id:
            return None
        try:
            resp = self._http.get(self._base_url(), params=self._params(address, "getabi", chain))
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("status") != "1":
                return None
            return data.get("result")
        except Exception:
            return None

    def get_source_code(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        chain_id = CHAIN_IDS.get(chain)
        if not chain_id:
            return None
        try:
            resp = self._http.get(self._base_url(), params=self._params(address, "getsourcecode", chain))
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("status") != "1" or not data.get("result"):
                return None
            return data["result"][0].get("SourceCode", "")
        except Exception:
            return None

    def get_contract_creation(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        try:
            resp = self._http.get(self._base_url(), params=self._params(address, "getcontractcreation", chain))
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("status") != "1" or not data.get("result"):
                return None
            return data["result"][0].get("contractCreator", "")
        except Exception:
            return None

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
