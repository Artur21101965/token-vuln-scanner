from functools import lru_cache
from typing import Optional
from evmole import contract_info

SELECTOR_DB: dict[str, str] = {
    "8129fc1c": "initialize()",
    "2e1a7d4d": "withdraw(uint256)",
    "6198e339": "withdraw(address,uint256)",
    "00f714ce": "sweep(address,uint256)",
    "d0679d34": "drain(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "3659cfe6": "upgradeTo(address)",
    "5c60da1b": "implementation()",
    "8da5cb5b": "owner()",
    "f2fde38b": "transferOwnership(address)",
    "a3b2b1fe": "setImplementation(address)",
    "d4e54b3d": "setImplementation(address)",
    "b69ef8a8": "collect(address)",
    "21df0da7": "sweep(address)",
    "b36a7c65": "sweepAll(address)",
    "9a7bff79": "claimFees()",
    "adf0a0e1": "claimOwnership()",
    "1c5b8f7b": "init(address)",
    "6a98c6a3": "init(address,address)",
    "a627c6c6": "__CLAIM_REWARDS",
    "c4d66de8": "__AUTOCLAIM",
    "77fbd300": "initialize(address,address)",
    "e30c3978": "initialize(address,address,address)",
    "948ea8a8": "initialize(address)",
    "7c8127fe": "init()",
    "dc4a49e2": "init(address[],uint256[])",
    "2b6c3bcc": "migrate(address)",
    "b68ad959": "emergencyWithdraw(address,uint256)",
    "3996ac90": "emergencyWithdraw(address)",
    "5312ea8e": "emergencyExit()",
    "f81b24b1": "setHandler(address,bool)",
    "51e34c9b": "setMinter(address,bool)",
    "0f4fc0f8": "updateImplementation(address)",
    "ab4b1af2": "addOperator(address)",
    "ad13b35d": "removeOperator(address)",
    "a1250e9f": "addToWhitelist(address)",
    "2e65c0dd": "removeFromWhitelist(address)",
    "8d9775fc": "whitelist(address,bool)",
    "db66042c": "withdrawAll()",
    "693d09d3": "withdrawTo(address,uint256)",
    "7c71ef48": "withdrawToken(address,uint256)",
    "088c7f1f": "withdrawTokens(address[],uint256[])",
    "811c39ab": "drainToken(address,address)",
    "278d88cf": "collect(address,uint256)",
    "dfb9e5a4": "collectAll()",
    "937f87c0": "collectTokens(address[],uint256[])",
}

NONPAYABLE_DANGEROUS_SELECTORS = {k for k, v in SELECTOR_DB.items()}


@lru_cache(maxsize=512)
def analyze_bytecode(code: str, selectors: bool = True,
                     arguments: bool = True,
                     state_mutability: bool = True):
    if not code or code == "0x" or len(code) < 10:
        return None
    try:
        return contract_info(code, selectors=selectors,
                             arguments=arguments,
                             state_mutability=state_mutability)
    except Exception:
        return None


def get_functions(code: str) -> list:
    info = analyze_bytecode(code)
    if info is None:
        return []
    return info.functions


def find_dangerous_functions(code: str) -> list[dict]:
    functions = get_functions(code)
    results = []
    for fn in functions:
        sel_hex = fn.selector.lower()
        if sel_hex in SELECTOR_DB:
            results.append({
                "selector": sel_hex,
                "signature": SELECTOR_DB[sel_hex],
                "arguments": fn.arguments,
                "state_mutability": fn.state_mutability,
                "offset": fn.bytecode_offset,
            })
        elif fn.state_mutability == "nonpayable" and fn.arguments in ("", "uint256", "address"):
            if fn.arguments == "":
                desc = "Nonpayable function with no args — possible kill/drain function"
            elif fn.arguments == "uint256":
                desc = "Nonpayable function taking uint256 — possible withdraw(uint256)"
            elif fn.arguments == "address":
                desc = "Nonpayable function taking address — possible transferOwnership"
            else:
                desc = f"Suspicious nonpayable function ({fn.arguments})"
            results.append({
                "selector": sel_hex,
                "signature": f"unknown({fn.arguments})",
                "arguments": fn.arguments,
                "state_mutability": fn.state_mutability,
                "offset": fn.bytecode_offset,
                "suspicious": True,
                "description": desc,
            })
    return results


def has_dangerous_function(code: str, selector: str) -> bool:
    functions = get_functions(code)
    sel_lower = selector.lower()
    return any(fn.selector.lower() == sel_lower for fn in functions)


def get_selectors(code: str) -> set[str]:
    functions = get_functions(code)
    return {fn.selector.lower() for fn in functions}
