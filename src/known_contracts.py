KNOWN_CONTRACTS = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": {
        "name": "WETH",
        "chain": "ethereum",
        "skip_checks": {"unprotected_withdraw"},
    },
    "0x4200000000000000000000000000000000000006": {
        "name": "WETH (Base)",
        "chain": "base",
        "skip_checks": {"unprotected_withdraw"},
    },
    "0x4200000000000000000000000000000000000023": {
        "name": "WETH (Blast)",
        "chain": "base",
        "skip_checks": {"unprotected_withdraw"},
    },
    "0x2170ed0880ac9a755fd29b2688956bd959f933f8": {
        "name": "WETH (BSC)",
        "chain": "bsc",
        "skip_checks": {"unprotected_withdraw"},
    },
    "0xe9dce63b9a6fb2c0315ec3b71cb3dc931de2a8e": {
        "name": "WETH (Arbitrum)",
        "chain": "arbitrum",
        "skip_checks": {"unprotected_withdraw"},
    },
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
        "name": "USDC",
        "chain": "ethereum",
        "skip_checks": {"unprotected_upgrade"},
    },
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {
        "name": "USDC (Base)",
        "chain": "base",
        "skip_checks": {"unprotected_upgrade"},
    },
}


def is_known_contract(address: str, chain: str) -> dict | None:
    key = address.lower()
    info = KNOWN_CONTRACTS.get(key)
    if info and info["chain"] == chain:
        return info
    return None
