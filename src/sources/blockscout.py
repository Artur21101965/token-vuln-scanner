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
    def __init__(self, max_pages: int = 3):
        self._max_pages = max_pages

    def fetch(self, chain: Chain) -> list[ContractTarget]:
        base = BLOCKSCOUT_URLS.get(chain)
        if not base:
            logger.warning("No Blockscout URL for %s", chain.name)
            return []

        targets: list[ContractTarget] = []
        next_params: dict | None = None

        with httpx.Client(timeout=30, follow_redirects=True) as client:
            for _ in range(self._max_pages):
                try:
                    params = next_params if next_params else None
                    resp = client.get(
                        f"{base}/smart-contracts",
                        params=params,
                        headers={"User-Agent": "token-vuln-scanner/0.1"},
                    )
                    if resp.status_code != 200:
                        logger.warning("Blockscout %s: HTTP %d", chain.name, resp.status_code)
                        break
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
                    next_params = data.get("next_page_params")
                    if not next_params:
                        break
                except Exception as e:
                    logger.error("Blockscout %s error: %s", chain.name, e)
                    break

        return targets


