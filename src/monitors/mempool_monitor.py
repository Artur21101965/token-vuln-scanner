import json
import logging
import os
import time
from typing import Optional
from src.rpc import RpcClient
from src.types import Chain
from src.known_contracts import KNOWN_CONTRACTS

logger = logging.getLogger(__name__)

REPORTS_DIR = "reports"
POLL_INTERVAL = 3
TOKEN_REFRESH_INTERVAL = 60

DANGEROUS_SELECTORS: dict[str, str] = {
    "8129fc1c": "initialize()",
    "f2fde38b": "transferOwnership(address)",
    "3659cfe6": "upgradeTo(address)",
    "40c10f19": "mint(address,uint256)",
    "2e1a7d4d": "withdraw(uint256)",
    "1c5b8f7b": "initialize(address,uint256,uint256)",  # typical with fee args
    "6a98c6a3": "initialize(address)",
    "a627c6c6": "initialize(uint256)",
    "aae7857b": "openTrading()",
    "4083d952": "enableTrading()",
    "2095d525": "unlock()",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "a3b2b1fe": "setSwapPair(address)",
    "baeb26e9": "removeLimits()",
    "bf03e2b8": "excludeFromFees(address,bool)",
    "d8ce34cd": "finalize()",
    "8da5cb5b": "owner() (read — possible probe)",
}

ALERT_CUTOFFS = {
    "initialize()", "transferOwnership(address)", "upgradeTo(address)",
    "mint(address,uint256)", "withdraw(uint256)", "setSwapPair(address)",
    "unlock()", "finalize()",
}


class MempoolMonitor:
    def __init__(self, rpc: RpcClient, chain: Chain):
        self._rpc = rpc
        self._chain = chain
        self._seen_txs: set[str] = set()
        self._known_tokens: set[str] = set()
        self._known_contracts: set[str] = {
            addr for addr, info in KNOWN_CONTRACTS.items()
            if info["chain"] == chain.name.lower()
        }
        self._last_refresh = 0.0
        self._last_block_hash = ""
        self._consecutive_empty = 0

    def refresh_tokens(self):
        """Load token addresses from reports directory."""
        chain_dir = os.path.join(REPORTS_DIR, self._chain.name.lower())
        if not os.path.isdir(chain_dir):
            return
        before = len(self._known_tokens)
        for addr in os.listdir(chain_dir):
            addr_lower = addr.lower()
            if not addr_lower.startswith("0x"):
                continue
            report_file = os.path.join(chain_dir, addr, "report.json")
            if os.path.isfile(report_file):
                self._known_tokens.add(addr_lower)
        after = len(self._known_tokens)
        if after > before:
            logger.info("MempoolMonitor loaded %d tokens for %s (+%d new)",
                        after, self._chain.name, after - before)

    def poll(self) -> int:
        now = time.time()
        if now - self._last_refresh > TOKEN_REFRESH_INTERVAL:
            self.refresh_tokens()
            self._last_refresh = now

        if not self._known_tokens:
            return 0

        try:
            block = self._rpc.call("eth_getBlockByNumber", ["pending", True])
        except Exception as exc:
            self._consecutive_empty += 1
            if self._consecutive_empty % 10 == 1:
                logger.debug("Pending block error for %s: %s", self._chain.name, exc)
            return 0

        self._consecutive_empty = 0

        block_hash = block.get("hash", "")
        if block_hash == self._last_block_hash:
            return 0
        self._last_block_hash = block_hash

        txs = block.get("transactions", [])
        alerts = 0
        for tx in txs:
            tx_hash = tx.get("hash", "")
            if not tx_hash or tx_hash in self._seen_txs:
                continue
            self._seen_txs.add(tx_hash)

            to_addr = (tx.get("to") or "").lower()
            if not to_addr or to_addr not in self._known_tokens:
                continue
            if to_addr in self._known_contracts:
                continue

            data = (tx.get("input") or tx.get("data") or "0x")
            selector = data[2:10].lower() if len(data) >= 10 else ""

            if selector in DANGEROUS_SELECTORS:
                func_name = DANGEROUS_SELECTORS[selector]
                priority = "HIGH" if selector in {k for k, v in DANGEROUS_SELECTORS.items() if v in ALERT_CUTOFFS} else "INFO"
                self._alert(tx_hash, to_addr, func_name, priority, tx)
                alerts += 1

        if alerts:
            logger.warning("MempoolMonitor on %s: %d suspicious TX in pending block",
                           self._chain.name, alerts)
        return alerts

    def _alert(self, tx_hash: str, token_addr: str, func_name: str,
               priority: str, tx: dict):
        tx_link = tx_hash[:18] + "..." if len(tx_hash) > 18 else tx_hash
        from_addr = (tx.get("from") or "unknown")[:14] + "..."

        value = int(tx.get("value", "0x0"), 16)
        value_str = f"{value / 1e18:.4f} ETH" if value > 0 else "0"

        msg = (
            f"\n{'='*50}\n"
            f"🚨 MEMPOOL ALERT [{self._chain.name}] | {priority}\n"
            f"   Token: {_explorer_link(self._chain, token_addr)}\n"
            f"   TX: {_etherscan_tx(self._chain, tx_hash)}\n"
            f"   Function: {func_name}\n"
            f"   From: {from_addr}\n"
            f"   Value: {value_str}\n"
            f"   Gas: {int(tx.get('gas', '0x0'), 16)}\n"
            f"{'='*50}"
        )
        logger.warning(msg)

    def run(self):
        logger.info("MempoolMonitor started for %s", self._chain.name)
        self.refresh_tokens()
        while True:
            try:
                self.poll()
            except Exception as exc:
                logger.error("MempoolMonitor error on %s: %s", self._chain.name, exc)
            time.sleep(POLL_INTERVAL)


def _explorer_link(chain: Chain, address: str) -> str:
    urls = {
        Chain.ETHEREUM: "https://etherscan.io/address/",
        Chain.BSC: "https://bscscan.com/address/",
        Chain.ARBITRUM: "https://arbiscan.io/address/",
        Chain.BASE: "https://basescan.org/address/",
        Chain.POLYGON: "https://polygonscan.com/address/",
        Chain.AVALANCHE: "https://snowtrace.io/address/",
        Chain.OPTIMISM: "https://optimistic.etherscan.io/address/",
    }
    url = urls.get(chain, "https://etherscan.io/address/")
    return f"{url}{address}"


def _etherscan_tx(chain: Chain, tx_hash: str) -> str:
    urls = {
        Chain.ETHEREUM: "https://etherscan.io/tx/",
        Chain.BSC: "https://bscscan.com/tx/",
        Chain.ARBITRUM: "https://arbiscan.io/tx/",
        Chain.BASE: "https://basescan.org/tx/",
        Chain.POLYGON: "https://polygonscan.com/tx/",
        Chain.AVALANCHE: "https://snowtrace.io/tx/",
        Chain.OPTIMISM: "https://optimistic.etherscan.io/tx/",
    }
    url = urls.get(chain, "https://etherscan.io/tx/")
    return f"{url}{tx_hash}"
