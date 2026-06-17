from typing import Optional
import httpx
from src.types import Chain


class ExplorerClient:
    def __init__(self, api_key: str = ""):
        self._key = api_key
        self._http = httpx.Client(timeout=15)

    def _base_url(self, chain: Chain) -> str:
        urls = {
            Chain.ETHEREUM: "https://api.etherscan.io",
            Chain.BSC: "https://api.bscscan.com",
            Chain.ARBITRUM: "https://api.arbiscan.io",
            Chain.BASE: "https://api.basescan.org",
            Chain.POLYGON: "https://api.polygonscan.com",
            Chain.AVALANCHE: "https://api.snowtrace.io",
            Chain.OPTIMISM: "https://api-optimistic.etherscan.io",
            Chain.ZKSYNC: "https://api-era.zksync.network",
            Chain.LINEA: "https://api.lineascan.build",
            Chain.SCROLL: "https://api.scrollscan.com",
        }
        return urls.get(chain, "")

    def get_abi(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        base = self._base_url(chain)
        if not base:
            return None
        params = {
            "module": "contract",
            "action": "getabi",
            "address": address,
            "apikey": self._key,
        }
        resp = self._http.get(f"{base}/api", params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "1":
            return None
        return data.get("result")

    def get_source_code(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        base = self._base_url(chain)
        if not base:
            return None
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self._key,
        }
        resp = self._http.get(f"{base}/api", params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "1" or not data.get("result"):
            return None
        return data["result"][0].get("SourceCode", "")

    def get_contract_creation(self, address: str, chain: Chain) -> Optional[str]:
        if chain == Chain.SOLANA:
            return None
        base = self._base_url(chain)
        if not base:
            return None
        params = {
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": address,
            "apikey": self._key,
        }
        try:
            resp = self._http.get(f"{base}/api", params=params, timeout=10)
            resp.raise_for_status()
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
