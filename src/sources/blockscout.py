import logging
import httpx
from src.types import Chain, ContractTarget

logger = logging.getLogger(__name__)

BLOCKSCOUT_URLS: dict[Chain, str] = {
    Chain.ETHEREUM: "https://eth.blockscout.com/api/v2",
    Chain.BSC: "https://bsc.blockscout.com/api/v2",
    Chain.POLYGON: "https://polygon.blockscout.com/api/v2",
    Chain.ARBITRUM: "https://arbitrum.blockscout.com/api/v2",
    Chain.BASE: "https://base.blockscout.com/api/v2",
    Chain.OPTIMISM: "https://optimism.blockscout.com/api/v2",
    Chain.AVALANCHE: "https://avalanche.blockscout.com/api/v2",
    Chain.ZKSYNC: "https://zksync.blockscout.com/api/v2",
    Chain.LINEA: "https://linea.blockscout.com/api/v2",
    Chain.SCROLL: "https://scroll.blockscout.com/api/v2",
}

class BlockscoutRecentSource:
    def __init__(self, max_pages: int = 3, page_size: int = 50):
        self._max_pages = max_pages
        self._page_size = page_size

    def fetch(self, chain: Chain) -> list[ContractTarget]:
        base = BLOCKSCOUT_URLS.get(chain)
        if not base:
            logger.warning("No Blockscout URL for %s", chain.name)
            return []

        targets: list[ContractTarget] = []
        with httpx.Client(timeout=30) as client:
            for page in range(1, self._max_pages + 1):
                try:
                    resp = client.get(
                        f"{base}/smart-contracts",
                        params={"page": page, "page_size": self._page_size},
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code != 200:
                        logger.warning("Blockscout %s page %d: HTTP %d", chain.name, page, resp.status_code)
                        continue
                    data = resp.json()
                    items = data.get("items", [])
                    if not items:
                        break
                    for item in items:
                        address = (item.get("address") or {}).get("hash", "")
                        if not address or not address.startswith("0x"):
                            continue
                        targets.append(ContractTarget(
                            chain=chain,
                            address=address.lower(),
                            source="blockscout",
                        ))
                except Exception as e:
                    logger.error("Blockscout %s page %d error: %s", chain.name, page, e)
                    continue

        return targets


