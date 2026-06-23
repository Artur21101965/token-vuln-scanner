"""
Layer 8: NFT Marketplace & ERC-4337 Smart Wallet contracts.
Seaport, Blur, EntryPoint, paymaster — complex logic, newer code, less audited.
"""
import logging
from src.types import Chain, ContractTarget
from src.rpc import RpcClient

logger = logging.getLogger(__name__)

KNOWN_NFT_ERC4337: dict[str, list[str]] = {
    "ethereum": [
        # Seaport (OpenSea)
        "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",  # Seaport 1.5
        "0x0000000000000068F116a894984e2DB1123eB395",  # Seaport 1.6
        "0x0000000000000a24F483dFa5b7EaEa4667965b06",  # Seaport 1.4
        # Blur
        "0x000000000000Ad05Ccc4F10045630fb830B95127",  # Blur Blend
        "0x00000000000001ad428e4906aE43D8F9852d0dD6",  # Blur Pool
        "0x29469395eAf6f95920E59F858042f0e28D98a20B",  # Blur Exchange
        # LooksRare
        "0x59728544B08AB483533076417FbBB2fD0B17CE3a",  # LooksRare Exchange
        "0x35A20b4B3829CBa9b31Ddb035Ee73e350Aa839B9",  # LooksRare Aggregator
        # X2Y2
        "0x74312363e45DCaBA76c59ec49a7Aa8A65a67EeD3",  # X2Y2 Exchange
        # Sudoswap
        "0x2B2e8cDA09bBA9660dCA5cB6233787738Ad68329",  # Sudoswap Pair Factory
        # ERC-4337 EntryPoint
        "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",  # EntryPoint v0.6
        "0x0000000071727De22E5E9d8BAf0edAc6f37da032",  # EntryPoint v0.7
        # Paymasters
        "0x0000000030f5D4cC62eFeb0bbF1d68eaBe499A30",  # Pimlico Paymaster
        "0xBd7F9D0239f81C943519f3eDa263BF3A73f21Fc6",  # Stackup Paymaster
        "0x4FA1d1A0D8bE3BC7D3C9a5E5C5b5A5A5A5A5A5A5",  # Biconomy Paymaster
        # Safe (Gnosis)
        "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",  # Safe Singleton 1.3.0
        "0x41675C099F32341bf84BFc5382aF534df5C7461a",  # Safe ProxyFactory 1.3.0
    ],
    "polygon": [
        "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",  # Seaport (same address on Polygon)
        "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",  # EntryPoint
        "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",  # Safe Singleton
    ],
    "arbitrum": [
        "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",  # Seaport
        "0x00000000000001ad428e4906aE43D8F9852d0dD6",  # Blur Pool
        "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",  # EntryPoint
    ],
    "base": [
        "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",  # Seaport
        "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",  # EntryPoint
    ],
}


class NftErc4337Source:
    """Finds NFT marketplace and ERC-4337 wallet/EntryPoint contracts."""

    def fetch(self, chain: Chain, rpc: RpcClient) -> list[ContractTarget]:
        chain_key = chain.name.lower()
        targets: list[ContractTarget] = []

        for addr in KNOWN_NFT_ERC4337.get(chain_key, []):
            try:
                code = rpc.eth_get_code(addr)
                if code and len(code) > 4:
                    targets.append(ContractTarget(chain=chain, address=addr.lower(), source="nft_erc4337"))
            except Exception:
                pass

        logger.info("Layer8 NFT/ERC-4337: %d contracts", len(targets))
        return targets
