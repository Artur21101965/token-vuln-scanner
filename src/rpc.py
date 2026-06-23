import time, os, tomllib
from typing import Any, Optional
import httpx

# Популярные публичные RPC (фолбэк если нет в конфиге)
DEFAULT_RPC_URLS = {
    "ethereum": [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://rpc.ankr.com/eth",
        "https://eth.drpc.org",
    ],
    "polygon": [
        "https://polygon-bor.publicnode.com",
        "https://polygon.llamarpc.com",
        "https://rpc.ankr.com/polygon",
        "https://polygon.drpc.org",
    ],
    "arbitrum": [
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum.llamarpc.com",
        "https://rpc.ankr.com/arbitrum",
    ],
    "base": [
        "https://mainnet.base.org",
        "https://base.llamarpc.com",
        "https://rpc.ankr.com/base",
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org",
        "https://bsc.llamarpc.com",
        "https://rpc.ankr.com/bsc",
        "https://binance.llamarpc.com",
    ],
    "optimism": [
        "https://mainnet.optimism.io",
        "https://optimism.llamarpc.com",
        "https://rpc.ankr.com/optimism",
    ],
    "avalanche": [
        "https://api.avax.network/ext/bc/C/rpc",
        "https://avalanche.llamarpc.com",
        "https://rpc.ankr.com/avalanche",
    ],
    "linea": [
        "https://rpc.linea.build",
        "https://linea.llamarpc.com",
    ],
    "scroll": [
        "https://rpc.scroll.io",
        "https://scroll.llamarpc.com",
    ],
}

# Tor SOCKS5 прокси
TOR_PROXY = "socks5://localhost:9050"


def _load_config():
    """Загружает config.toml."""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.toml"
    )
    if os.path.exists(config_path):
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    return {}


def is_tor_enabled() -> bool:
    """Проверяет, включён ли Tor в конфиге."""
    cfg = _load_config()
    return cfg.get("tor", {}).get("enabled", False)


def load_rpc_urls(chain: str) -> list[str]:
    """Загружает список RPC URL для цепи из конфига или дефолтов."""
    cfg = _load_config()
    rpc_section = cfg.get("rpc", {})

    # Поддержка множественных URL: rpc.ethereum = "url1,url2,url3"
    raw = rpc_section.get(chain, "")
    if raw:
        urls = [u.strip() for u in raw.split(",") if u.strip()]
        if urls:
            return urls

    # Поддержка нового формата: rpc.ethereum_urls = ["url1", "url2"]
    urls_list = rpc_section.get(f"{chain}_urls", [])
    if urls_list:
        return urls_list if isinstance(urls_list, list) else [urls_list]

    return DEFAULT_RPC_URLS.get(chain, [])


def is_tor_available() -> bool:
    """Проверяет, запущен ли Tor (quick TCP connect)."""
    try:
        import socket
        s = socket.socket()
        s.settimeout(1)
        s.connect(("127.0.0.1", 9050))
        s.close()
        return True
    except Exception:
        return False


class RpcClient:
    def __init__(self, rpc_url: str, max_retries: int = 3, use_tor: bool = False):
        self._url = rpc_url
        self._max_retries = max_retries

        if use_tor and is_tor_available():
            transport = httpx.HTTPTransport(proxy=TOR_PROXY)
            self._http = httpx.Client(timeout=30, transport=transport)
        else:
            self._http = httpx.Client(timeout=30)

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        }
        last_error = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._http.post(self._url, json=payload)
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < self._max_retries:
                        wait = 2 ** attempt
                        time.sleep(wait)
                        continue
                resp.raise_for_status()
                data = resp.json()
                if "error" in data:
                    err = data["error"]
                    msg = str(err.get("message", ""))
                    if ("rate limit" in msg.lower() or "too many requests" in msg.lower()) and attempt < self._max_retries:
                        time.sleep(2 ** attempt)
                        continue
                    raise RuntimeError(f"RPC error: {err}")
                return data["result"]
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt < self._max_retries:
                    time.sleep(2 ** attempt)
                    continue
                last_error = e
            except (httpx.RequestError, httpx.TimeoutException) as e:
                if attempt < self._max_retries:
                    time.sleep(2 ** attempt)
                    last_error = e
                    continue
                last_error = e
        raise RuntimeError(f"RPC call failed after {self._max_retries} retries: {last_error}")

    def eth_call(self, to: str, data: str, block: str = "latest",
                 from_address: str = "", value: str = "") -> str:
        tx = {"to": to, "data": data}
        if from_address:
            tx["from"] = from_address
        if value:
            tx["value"] = value
        return self.call("eth_call", [tx, block])

    def eth_get_code(self, address: str, block: str = "latest") -> str:
        return self.call("eth_getCode", [address, block])

    def eth_get_balance(self, address: str, block: str = "latest") -> str:
        return self.call("eth_getBalance", [address, block])

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> str:
        return self.call("eth_getStorageAt", [address, hex(slot), block])

    def get_logs(self, from_block: str, to_block: str, address: str,
                 topics: Optional[list] = None) -> list[dict]:
        params: dict = {
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": address,
        }
        if topics:
            params["topics"] = topics
        return self.call("eth_getLogs", [params])

    def get_block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MultiRpcClient:
    """Round-robin RPC client across multiple endpoints to avoid rate limits.
    Поддерживает Tor-прокси и авто-загрузку URL из конфига."""

    def __init__(self, rpc_urls: list[str] | None = None, chain: str = "",
                 max_retries: int = 2, use_tor: bool = False):
        if rpc_urls is None:
            if chain:
                rpc_urls = load_rpc_urls(chain)
            if not rpc_urls:
                rpc_urls = ["https://ethereum-rpc.publicnode.com"]

        self._use_tor = use_tor or (is_tor_enabled() and is_tor_available())
        self._clients = [RpcClient(url, max_retries=max_retries, use_tor=self._use_tor) for url in rpc_urls]
        self._idx = 0

    def _next(self) -> RpcClient:
        client = self._clients[self._idx]
        self._idx = (self._idx + 1) % len(self._clients)
        return client

    def call(self, method: str, params: list = None) -> Any:
        for _ in range(len(self._clients)):
            client = self._next()
            try:
                return client.call(method, params)
            except Exception:
                continue
        raise RuntimeError(f"All {len(self._clients)} RPC endpoints failed for {method}")

    def eth_call(self, to: str, data: str, block: str = "latest",
                 from_address: str = "", value: str = "") -> str:
        for _ in range(len(self._clients)):
            client = self._next()
            try:
                return client.eth_call(to, data, block, from_address, value)
            except Exception:
                continue
        raise RuntimeError("All RPC endpoints failed for eth_call")

    def eth_get_code(self, address: str, block: str = "latest") -> str:
        return self.call("eth_getCode", [address, block])

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> str:
        return self.call("eth_getStorageAt", [address, hex(slot), block])

    def get_logs(self, from_block: str, to_block: str, address: str,
                 topics: list = None) -> list[dict]:
        params = {"fromBlock": from_block, "toBlock": to_block, "address": address}
        if topics:
            params["topics"] = topics
        return self.call("eth_getLogs", [params])

    def get_block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def close(self):
        for c in self._clients:
            c.close()
