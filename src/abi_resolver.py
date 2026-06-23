from typing import Optional
import httpx
from eth_utils import keccak
from eth_abi import encode
from src.types import Chain


BLOCKSCOUT_URLS: dict[str, str] = {
    "ethereum": "https://eth.blockscout.com",
    "bsc": "https://bsc.blockscout.com",
    "polygon": "https://polygon.blockscout.com",
    "arbitrum": "https://arbitrum.blockscout.com",
    "base": "https://base.blockscout.com",
    "optimism": "https://optimism.blockscout.com",
    "avalanche": "https://avalanche.blockscout.com",
    "zksync": "https://zksync.blockscout.com",
    "linea": "https://linea.blockscout.com",
    "scroll": "https://scroll.blockscout.com",
}

FOURBYTE_URL = "https://api.4byte.directory/api/v1/signatures/"

DUMMY_ADDR = "0x0000000000000000000000000000000000000002"

_abi_cache: dict[tuple[str, str], list[dict] | None] = {}
_4byte_cache: dict[str, list[str]] = {}


class AbiResolver:
    def __init__(self):
        self._http = httpx.Client(timeout=10)

    def get_abi(self, address: str, chain: Chain) -> Optional[list[dict]]:
        key = (chain.value, address.lower())
        if key in _abi_cache:
            return _abi_cache[key]

        url = BLOCKSCOUT_URLS.get(chain.value)
        if url:
            abi = self._fetch_blockscout(url, address)
            if abi:
                _abi_cache[key] = abi
                return abi

        _abi_cache[key] = None
        return None

    def get_function_by_selector(self, address: str, chain: Chain, selector: str) -> Optional[dict]:
        abi = self.get_abi(address, chain)
        if not abi:
            return None
        sig = selector.lower().replace("0x", "")
        for item in abi:
            if item.get("type") != "function":
                continue
            name = item["name"]
            types = [i["type"] for i in item.get("inputs", [])]
            computed = keccak(f"{name}({','.join(types)})".encode())[:4].hex()
            if computed == sig:
                return item
        return None

    def get_function_name(self, address: str, chain: Chain, selector: str) -> Optional[str]:
        func = self.get_function_by_selector(address, chain, selector)
        if func:
            types = [i["type"] for i in func.get("inputs", [])]
            return f"{func['name']}({','.join(types)})"

        return self._lookup_4byte(selector)

    def build_calldata(self, func: dict, override_address: str | None = None) -> str:
        name = func["name"]
        inputs = func.get("inputs", [])
        types = [i["type"] for i in inputs]
        args = []
        addr_used = False
        for i, t in enumerate(types):
            val = _dummy_value(t)
            if override_address is not None and not addr_used and t == "address":
                val = override_address
                addr_used = True
            args.append(val)
        selector_hex = keccak(f"{name}({','.join(types)})".encode())[:4].hex()
        encoded = encode(types, args).hex()
        return selector_hex + encoded

    def _fetch_blockscout(self, base_url: str, address: str) -> Optional[list[dict]]:
        try:
            resp = self._http.get(
                f"{base_url}/api",
                params={"module": "contract", "action": "getabi", "address": address},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "1":
                return None
            raw = data.get("result", "")
            if isinstance(raw, str):
                import json
                return json.loads(raw)
            return raw
        except Exception:
            return None

    def fetch_created_contracts(self, deployer: str, chain: Chain) -> list[str]:
        chain_key = chain.name.lower()
        base_url = BLOCKSCOUT_URLS.get(chain_key)
        if not base_url:
            return []
        try:
            resp = self._http.get(
                f"{base_url}/api/v2/addresses/{deployer}/created-contracts",
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("items", [])
            return [item["created_contract"]["hash"] for item in items]
        except Exception:
            return []

    def _lookup_4byte(self, selector: str) -> Optional[str]:
        sig = selector.lower().replace("0x", "")
        if sig in _4byte_cache:
            names = _4byte_cache[sig]
            return names[0] if names else None

        try:
            resp = self._http.get(
                f"{FOURBYTE_URL}?hex_signature=0x{sig}",
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            names = [r["text_signature"] for r in results]
            _4byte_cache[sig] = names
            return names[0] if names else None
        except Exception:
            _4byte_cache[sig] = []
            return None


def _dummy_value(typ: str):
    if typ.endswith("[]"):
        return []
    if typ == "address":
        return DUMMY_ADDR
    if typ.startswith("uint") or typ.startswith("int"):
        return 0
    if typ == "bool":
        return False
    if typ == "bytes32":
        return b"\x00" * 32
    if typ.startswith("bytes"):
        return b""
    if typ == "string":
        return ""
    return 0


def close(self):
    self._http.close()
