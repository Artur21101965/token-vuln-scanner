"""
Layer 7: MEV Searcher contracts — find bots that sandwich/hunt MEV.
These hold ETH and often have buggy code or unprotected functions.
"""
import logging
from src.types import Chain, ContractTarget
from src.rpc import RpcClient

logger = logging.getLogger(__name__)

# Known MEV searcher contracts (verified from Etherscan/Flashbots)
KNOWN_SEARCHERS: dict[str, list[str]] = {
    "ethereum": [
        "0x0000000000007F150Bd6f54c40A34d7C3d5e9f56",  # jaredfromsubway
        "0x6B75d8AF000000e20B7a7DDf000Ba900b4009A80",  # beaverbuild
        "0xA57B8a5584442B467b4689F1144D269d096A3daF",  # rsync-builder
        "0x0000000000d41c96294CCdaC8612Cb4eC0B84949",  # bloXroute
        "0x1f2F10D1C40777AE1Da742455c65828FF36Df387",  # manifold
        "0x3D7e469FA25eCe0e9a585EffbE21C7e97Dd95Cc4",  # beaver
        "0xae2Fc483527B8EF99EB5D9B44875F005ba1FaE13",  # jaredfromsubway.eth v2
        "0x43a5A7bfa5A94728C0b0D4bA35dA287AF05fceC3",  # banana
        "0x07e828A4d4FfDAF8e3E2C7D39cb12A8eEfb54448",  # c0ffeebabe
    ],
    "polygon": [
        "0xDef1C0ded9bec7F1a1670819833240f027b25EfF",  # 0x (also trades on Polygon)
    ],
}

# Builders/relays that deploy searcher contracts
BUILDER_ADDRESSES = [
    "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5",  # Flashbots Builder
    "0x1F9090aaE28b8a3dCeaDf281B0F12828e676c326",  # rsync-builder
    "0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990",  # BeaverBuild
    "0x3a7e5C6d204fD5d4866824Ca5245d78DcF0AcE16",  # Titan Builder
]


class MevSearcherSource:
    """Finds MEV searcher/bot contracts via known addresses and builder deployers."""

    def __init__(self, max_results: int = 100):
        self._max = max_results

    def fetch(self, chain: Chain, rpc: RpcClient) -> list[ContractTarget]:
        chain_key = chain.name.lower()
        targets: list[ContractTarget] = []

        # Known searcher addresses
        for addr in KNOWN_SEARCHERS.get(chain_key, []):
            try:
                code = rpc.eth_get_code(addr)
                if code and len(code) > 4:
                    targets.append(ContractTarget(chain=chain, address=addr.lower(), source="mev_searcher"))
            except Exception:
                pass

        # Find contracts deployed by known builders
        try:
            from src.abi_resolver import AbiResolver
            resolver = AbiResolver()
            for builder in BUILDER_ADDRESSES[:2]:  # limit to avoid rate limits
                try:
                    children = resolver.fetch_created_contracts(builder, chain)
                    for child in children[:50]:
                        targets.append(ContractTarget(chain=chain, address=child.lower(), source="mev_child"))
                        if len(targets) >= self._max:
                            break
                except Exception:
                    continue
        except Exception:
            pass

        logger.info("Layer7 MEV searchers: %d contracts", len(targets))
        return targets[:self._max]
