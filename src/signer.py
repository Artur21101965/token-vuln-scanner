"""Load private keys and sign transactions for exploit execution."""
import os
import logging
import tomllib
from typing import Optional
from eth_account import Account
from eth_account.signers.local import LocalAccount
from src.types import Chain

logger = logging.getLogger(__name__)
CONFIG_PATH = "config.toml"


def _load_config(path: str = CONFIG_PATH) -> dict:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def load_evm_private_key(path: str = CONFIG_PATH) -> Optional[LocalAccount]:
    cfg = _load_config(path)
    key = cfg.get("executor", {}).get("evm_private_key", "") or os.environ.get("EVM_PRIVATE_KEY", "")
    if not key:
        return None
    key = key.strip()
    if not key.startswith("0x"):
        key = "0x" + key
    try:
        account = Account.from_key(key)
        logger.info("EVM signer loaded: %s", account.address)
        return account
    except Exception as e:
        logger.error("Failed to load EVM private key: %s", e)
        return None


def load_solana_private_key(path: str = CONFIG_PATH) -> Optional[str]:
    """Load Solana private key as base58 string."""
    cfg = _load_config(path)
    key = cfg.get("executor", {}).get("solana_private_key", "") or os.environ.get("SOLANA_PRIVATE_KEY", "")
    return key.strip() or None


def get_receive_address(chain: Chain, path: str = CONFIG_PATH) -> str:
    """Get receive address for exploit profits."""
    cfg = _load_config(path)
    wallets = cfg.get("wallet", {})
    fallback = cfg.get("executor", {}).get("receive_address", "")

    chain_name = chain.name.lower()
    addr = wallets.get(chain_name, "") or fallback
    return addr.strip()
