import time
from typing import Any, Optional
import httpx


class RpcClient:
    def __init__(self, rpc_url: str, max_retries: int = 3):
        self._url = rpc_url
        self._max_retries = max_retries
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
    """Round-robin RPC client across multiple endpoints to avoid rate limits."""
    def __init__(self, rpc_urls: list[str], max_retries: int = 2):
        self._clients = [RpcClient(url, max_retries=max_retries) for url in rpc_urls]
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
