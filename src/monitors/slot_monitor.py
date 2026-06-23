import json
import os
import logging
from typing import Optional
from src.rpc import RpcClient
from src.types import Chain
from src.data import DataCollector

logger = logging.getLogger(__name__)

OWNER_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
MONITORED_SLOTS = [OWNER_SLOT, EIP1967_IMPL_SLOT, EIP1967_ADMIN_SLOT]


class SlotMonitor:
    def __init__(self, data_collector: DataCollector, rpc: RpcClient, chain: Chain, state_dir: str = "reports"):
        self._data = data_collector
        self._rpc = rpc
        self._chain = chain
        self._state_dir = state_dir

    def _snapshot_path(self, token_address: str) -> str:
        chain_dir = self._chain.name.lower()
        return os.path.join(self._state_dir, chain_dir, token_address, "slots.json")

    def record_snapshot(self, token_address: str) -> dict[str, str]:
        snap: dict[str, str] = {}
        for slot in MONITORED_SLOTS:
            try:
                val = self._rpc.get_storage_at(token_address, int(slot, 16))
                if val and val != "0x" + "00" * 32:
                    snap[slot] = val
            except Exception:
                pass
        path = self._snapshot_path(token_address)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "w") as f:
                json.dump(snap, f)
        except Exception as exc:
            logger.debug("Failed to save slot snapshot for %s: %s", token_address, exc)
        return snap

    def check_for_changes(self, token_address: str) -> list[dict]:
        path = self._snapshot_path(token_address)
        if not os.path.exists(path):
            return []
        try:
            with open(path) as f:
                old = json.load(f)
        except Exception:
            return []

        changes: list[dict] = []
        for slot in MONITORED_SLOTS:
            if slot not in old:
                continue
            try:
                current = self._rpc.get_storage_at(token_address, int(slot, 16))
            except Exception:
                continue
            old_val = old[slot]
            if current and current.lower() != old_val.lower():
                slot_name = {
                    OWNER_SLOT: "owner",
                    EIP1967_IMPL_SLOT: "proxy_implementation",
                    EIP1967_ADMIN_SLOT: "proxy_admin",
                }.get(slot, slot)
                changes.append({
                    "slot": slot_name,
                    "previous": old_val,
                    "current": current,
                })
        if changes:
            self.record_snapshot(token_address)
        return changes
