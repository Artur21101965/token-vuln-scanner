from typing import Any, Optional
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

    def eth_call(self, to: str, data: str, block: str = "latest",
                 from_address: str = "") -> str:
        tx = {"to": to, "data": data}
        if from_address:
            tx["from"] = from_address
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
