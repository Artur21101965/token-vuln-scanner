"""Source: Uniswap V2 PairCreated events — finds all LP pair contracts."""
import logging
from src.types import Chain, ContractTarget
from src.rpc import RpcClient

logger = logging.getLogger(__name__)

# Uniswap V2 Factory on major chains
UNISWAP_V2_FACTORIES: dict[Chain, str] = {
    Chain.ETHEREUM: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
    Chain.POLYGON: "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32",
    Chain.ARBITRUM: "0xf1D7CC64Fb4452F05c498126312eBE29f30Fbcf9",
    Chain.BASE: "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
    Chain.BSC: "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    Chain.AVALANCHE: "0x9e5A52f57b3038F1B8EeE45F28b3C196d18efFB8",
    Chain.OPTIMISM: "0x0c3c1c532F1e39EdF36BE9Fe0bD1417613f55BB9",
}

# PairCreated event signature
PAIR_CREATED_TOPIC = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"


class UniswapV2PairSource:
    """Discovers Uniswap V2 LP pair contracts via PairCreated events."""

    def __init__(self, max_pairs: int = 500, from_block: int = 0):
        self._max_pairs = max_pairs
        self._from_block = from_block

    def fetch(self, chain: Chain, rpc: RpcClient) -> list[ContractTarget]:
        factory = UNISWAP_V2_FACTORIES.get(chain)
        if not factory:
            return []

        targets: list[ContractTarget] = []
        try:
            current_block = rpc.get_block_number()
            block_step = 5000  # eth_getLogs range limit
            from_b = max(self._from_block, current_block - 1000000)  # last ~1M blocks

            collected = 0
            for start in range(from_b, current_block, block_step):
                if collected >= self._max_pairs:
                    break
                end = min(start + block_step - 1, current_block)

                try:
                    logs = rpc.get_logs(
                        hex(start), hex(end),
                        factory,
                        [PAIR_CREATED_TOPIC],
                    )
                except Exception:
                    continue

                for log in logs:
                    if collected >= self._max_pairs:
                        break
                    # PairCreated event: topics[1]=token0, topics[2]=token1, data=pair
                    pair_addr = "0x" + log.get("data", "")[-40:] if len(log.get("data", "")) >= 40 else ""
                    if not pair_addr or pair_addr == "0x":
                        # Some chains encode pair in topics[3]
                        topics = log.get("topics", [])
                        if len(topics) > 3:
                            pair_addr = "0x" + topics[3][-40:]

                    if pair_addr and pair_addr != "0x" and len(pair_addr) == 42:
                        targets.append(ContractTarget(
                            chain=chain,
                            address=pair_addr.lower(),
                            source="uniswap_v2_pair",
                        ))
                        collected += 1

            logger.info("Uniswap V2 %s: found %d pairs", chain.name, len(targets))
        except Exception as e:
            logger.error("Uniswap V2 %s error: %s", chain.name, e)

        return targets
