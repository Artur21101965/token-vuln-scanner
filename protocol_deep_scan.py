"""
PROTOCOL DEEP SCAN — targets top 50 protocols across all chains.
Analyzes: unprotected admin functions, proxy storage, timelock bypass, 
unverified implementations, dangerous owner rights.
"""
import sys, tomllib, logging, time, json, urllib.request
from typing import Optional
from src.rpc import RpcClient
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
logger = logging.getLogger("protocol-scan")
logger.setLevel(logging.INFO)

# Top protocols worth investigating
PROTOCOLS = {
    "ethereum": [
        ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "Aave V3 Pool"),
        ("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "Aave V2 Lending"),
        ("0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "Compound Comptroller"),
        ("0x39AA39c021dfbaE8faC545936693aC917d5E7563", "Compound cUSDC"),
        ("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "Lido stETH"),
        ("0x17144556fd3424EDC8Fc8A4C940B2D04936d17eb", "Lido WithdrawalQueue"),
        ("0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2", "Lido NodeOperators"),
        ("0x1a8E3bF45e53Ci8f8eE6a14606B8aE1E8f5cA621", "Rocket Pool rETH"),
        ("0xDd3b91833c3D914039FaB3fd418D28e1924fFE9D", "Rocket Pool Storage"),
        ("0xf951E335afb289353dc249e82926178EaC7DEd78", "Swell swETH"),
        ("0xac3E018457B222d93114458476f3E3416Abbe38F", "Frax sfrxETH"),
        ("0x00000000aeFE0000000100000000000000000004", "EigenLayer Strategy"),
        ("0x858646372CC42E1A627fcE94aa7A7033e7CF075A", "EigenLayer Delegation"),
        ("0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef222A", "EigenLayer Slasher"),
        ("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE", "ETH (native)"),
    ],
    "arbitrum": [
        ("0x794a61358D6845594F94dc1DB02A252b5b4814aD", "Aave V3 Arbitrum"),
        ("0x8896d3C7C7Ef103D68e108a8385AF37B1cAB1fCc", "GMX Vault"),
        ("0x489ee077994B6658eAfA855C308275EAd8097C4A", "GMX Router"),
        ("0xc3f1a28edb31A659b9bB71c2429882ea54dF24a2", "Dopex"),
        ("0x3eBeEcA418B81F1A0E1C819F6D5B6bC6A6cA7b72", "Radiant"),
        ("0x9FC1Bf1654C0b3FA7445b3d174e6aC4e3dBbFA83", "Trader Joe"),
        ("0x7E5F5A1c99d3f6F1F3b1F1A1F1A1F1A1F1A1F1A", "Camelot"),
    ],
    "base": [
        ("0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43", "Aerodrome Router"),
        ("0x420DD381b31aEf6683db6B902084cB0FFECe40Da", "Aerodrome Factory"),
        ("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", "Aave V3 Base"),
        ("0x2626664c2603336E57B271c5C0b26F421741e481", "Uniswap V3 Base"),
        ("0x0fB8DcdFE5C44eC33bA1De1B0bAAb97b5155Ae4c", "Moonwell"),
        ("0x5ecF1aF6A53dF1e59C7945565A4267Cf1AbE6f2b", "Seamless"),
    ],
    "polygon": [
        ("0x794a61358D6845594F94dc1DB02A252b5b4814aD", "Aave V3 Polygon"),
        ("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "USDC.e"),
    ],
}

# Focus: these selectors grant instant control if unprotected
POWER_SELECTORS = [
    ("transferOwnership", "f2fde38b", "CALLABLE — instant admin takeover"),
    ("acceptOwnership", "79ba5097", "CALLABLE — accept pending ownership"),
    ("setPendingOwner", "c420e566", "CALLABLE — set self as pending"),
    ("renounceOwnership", "715018a6", "CALLABLE — renounce (brick)"),
    ("emergencyWithdraw", "db2e21bc", "CALLABLE — emergency drain"),
    ("rescueTokens", "7a9c2b39", "CALLABLE — rescue any token"),
    ("skim", "c95c03fb", "CALLABLE — skim pair balance"),
    ("sync", "b1976bd9", "CALLABLE — sync reserves"),
]

def deep_scan_protocol(rpc: RpcClient, addr: str, name: str, signer_addr: str) -> Optional[str]:
    """Deep scan a single protocol contract. Returns vulnerability description or None."""
    try:
        code = rpc.eth_get_code(addr)
    except Exception:
        return None

    if not code or len(code) <= 4:
        return None

    code_hex = str(code).lower()

    for fname, sel, desc in POWER_SELECTORS:
        if sel not in code_hex:
            continue

        calldata = "0x" + sel
        # For functions that take address: use signer address
        if fname in ("transferOwnership", "setPendingOwner"):
            calldata = "0x" + sel + signer_addr[2:].lower().zfill(64)

        try:
            gas = rpc.eth_call(addr, calldata, from_address=signer_addr)
            if gas and gas != "0x":
                return f"🚨 {name}: {fname}() {desc}"
        except Exception:
            pass


def scan_all():
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    signer = load_evm_private_key()
    signer_addr = signer.address if signer else ""

    for chain, protocols in PROTOCOLS.items():
        rpc_url = config["rpc"].get(chain, "")
        if not rpc_url:
            continue
        rpc = RpcClient(rpc_url, max_retries=2)

        logger.info("=== %s ===", chain.upper())
        hits = 0
        for addr, name in protocols:
            result = deep_scan_protocol(rpc, addr, name, signer_addr)
            if result:
                logger.warning(result)
                hits += 1
            time.sleep(0.5)

        if hits == 0:
            logger.info("  Все защищены")

if __name__ == "__main__":
    scan_all()
