"""Shared utilities for Solana token analysis.

SPL Token Mint account layout (82 bytes):
  0-3:   mint_authority_option  — u32 little-endian (COption<Pubkey>)
  4-35:  mint_authority         — 32 bytes (Pubkey)
  36-43: supply                 — u64 little-endian
  44:    decimals               — u8
  45:    is_initialized         — u8 (bool)
  46-49: freeze_authority_option — u32 little-endian (COption<Pubkey>)
  50-81: freeze_authority       — 32 bytes (Pubkey)
"""
import base64
import binascii
import struct
from typing import Optional


SOL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"


def _decode_coption(data: bytes, offset: int) -> tuple[int, str]:
    """Decode a COption<Pubkey> at offset, returns (option, hex_key)."""
    if offset + 36 > len(data):
        return 0, ""
    option = struct.unpack_from("<I", data, offset)[0]
    key = binascii.hexlify(data[offset + 4: offset + 36]).decode() if option > 0 else ""
    return option, key


def parse_mint_account(raw_base64: str) -> dict:
    """Parse a Solana SPL Token mint account from base64-encoded data."""
    try:
        data = base64.b64decode(raw_base64)
    except Exception:
        return {}

    if len(data) < 82:
        return {}

    mint_opt, mint_auth = _decode_coption(data, 0)
    supply = struct.unpack_from("<Q", data, 36)[0]
    decimals = data[44]
    freeze_opt, freeze_auth = _decode_coption(data, 46)

    return {
        "mint_authority_option": mint_opt,
        "mint_authority": mint_auth,
        "freeze_authority_option": freeze_opt,
        "freeze_authority": freeze_auth,
        "supply": supply,
        "decimals": decimals,
    }


def get_mint_account(ctx) -> Optional[dict]:
    """Fetch and parse a Solana mint account via RPC."""
    try:
        result = ctx.rpc.call("getAccountInfo", [
            ctx.token.address,
            {"encoding": "base64"},
        ])
    except Exception:
        return None

    info = result.get("result") or result
    account = info.get("value") or info if isinstance(info, dict) else {}
    raw_data = ""
    if isinstance(account, dict):
        raw_data = (account.get("data") or [None, None])[0] or ""

    if not raw_data:
        return None

    return parse_mint_account(raw_data)


def hex_to_base58(hex_str: str) -> str:
    """Convert hex string to Solana base58 address."""
    try:
        from solders.pubkey import Pubkey
        raw = binascii.unhexlify(hex_str)
        return str(Pubkey.from_bytes(raw))
    except ImportError:
        return hex_str
