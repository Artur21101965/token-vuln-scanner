from typing import Optional

from src.evm.disassembler import disassemble


def parse_dispatch_table(bytecode: str) -> tuple[dict[str, int], Optional[bool]]:
    instrs = disassemble(bytecode)
    if not instrs:
        return {}, None

    selectors: dict[str, int] = {}
    has_fallback: Optional[bool] = None
    last_jumpi_idx = -1

    i = 0
    while i < len(instrs):
        inst = instrs[i]
        if (
            inst.name == "DUP1"
            and i + 4 < len(instrs)
            and instrs[i + 1].name.startswith("PUSH")
            and len(instrs[i + 1].push_data) in (2, 3, 4)
            and instrs[i + 2].name == "EQ"
            and instrs[i + 3].name.startswith("PUSH")
            and instrs[i + 4].name == "JUMPI"
        ):
            selector_bytes = instrs[i + 1].push_data
            dest_bytes = instrs[i + 3].push_data
            selector_hex = selector_bytes.hex()
            dest = int.from_bytes(dest_bytes, "big")
            selectors[selector_hex] = dest
            last_jumpi_idx = i + 4
            i += 5
        else:
            i += 1

    if selectors:
        has_code_after_dispatch = False
        for j in range(last_jumpi_idx + 1, len(instrs)):
            if instrs[j].name not in ("REVERT", "INVALID", "STOP", "JUMPDEST"):
                has_code_after_dispatch = True
                break
        has_fallback = has_code_after_dispatch
    else:
        has_fallback = None

    return selectors, has_fallback


def is_selector_in_dispatch(bytecode: str, selector_hex: str) -> bool:
    selectors, _ = parse_dispatch_table(bytecode)
    return selector_hex in selectors


def get_callable_selectors(bytecode: str) -> set[str]:
    selectors, _ = parse_dispatch_table(bytecode)
    return set(selectors.keys())
