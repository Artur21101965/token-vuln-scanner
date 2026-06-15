from typing import Any
import httpx


class RpcClient:
    def __init__(self, rpc_url: str):
        self._url = rpc_url
        self._http = httpx.Client(timeout=30)

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        }
        resp = self._http.post(self._url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"RPC error: {data['error']}")
        return data["result"]

    def eth_call(self, to: str, data: str, block: str = "latest") -> str:
        return self.call("eth_call", [{"to": to, "data": data}, block])

    def eth_get_code(self, address: str, block: str = "latest") -> str:
        return self.call("eth_getCode", [address, block])

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> str:
        return self.call("eth_getStorageAt", [address, hex(slot), block])

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
