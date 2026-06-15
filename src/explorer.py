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
