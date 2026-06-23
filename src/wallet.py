"""Load wallet addresses from config for exploit simulation."""
import tomllib
from typing import Optional
from src.types import Chain

CONFIG_PATH = "config.toml"


def _is_valid_evm(addr: str) -> bool:
    return addr.startswith("0x") and len(addr) == 42


def _is_valid_solana(addr: str) -> bool:
    if not 32 <= len(addr) <= 44:
        return False
    try:
        from solders.pubkey import Pubkey
        Pubkey.from_string(addr)
        return True
    except Exception:
        return False


def load_wallet_addresses(path: str = CONFIG_PATH) -> dict[Chain, str]:
    wallets: dict[Chain, str] = {}
    try:
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
    except Exception:
        return wallets

    wcfg = cfg.get("wallet", {})
    for key, addr in wcfg.items():
        try:
            chain = Chain.from_str(key)
            addr = addr.strip()
            if chain == Chain.SOLANA:
                if _is_valid_solana(addr):
                    wallets[chain] = addr
            else:
                if _is_valid_evm(addr):
                    wallets[chain] = addr.lower()
        except (ValueError, KeyError):
            continue
    return wallets
