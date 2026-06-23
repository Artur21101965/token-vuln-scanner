from src.types import Chain

FACTORIES: dict[Chain, list[dict]] = {
    Chain.ETHEREUM: [
        {"address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", "dex": "Uniswap V2"},
    ],
    Chain.BSC: [
        {"address": "0xcA143Ce33Fe78f04f7803C2aE0e0cC6b4bE9A146", "dex": "PancakeSwap V2"},
    ],
    Chain.ARBITRUM: [
        {"address": "0xf1D7CC64Fb4452F05c498126312eBE29f30Fbcf9", "dex": "Uniswap V2"},
        {"address": "0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E", "dex": "Camelot"},
    ],
    Chain.BASE: [
        {"address": "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6", "dex": "Uniswap V2"},
    ],
    Chain.POLYGON: [
        {"address": "0x9e5A52f57b3038F1B8EeE45F28b3C1969e1D1b79", "dex": "QuickSwap"},
        {"address": "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32", "dex": "Uniswap V2"},
    ],
    Chain.AVALANCHE: [
        {"address": "0x9e5A52f57b3038F1B8EeE45F28b3C1969e1D1b79", "dex": "Trader Joe V2"},
        {"address": "0x794a61358D6845594F94dc1DB02A252b5b4814aD", "dex": "Uniswap V2"},
    ],
    Chain.OPTIMISM: [
        {"address": "0x0c83E74c2Ce9F6bB6c1E396150872C834bE3E623", "dex": "Uniswap V2"},
    ],
}

PAIR_CREATED_TOPIC = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
