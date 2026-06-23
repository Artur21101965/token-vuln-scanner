"""
WHALE HUNTER — targeted scan of ONLY high-value contracts.
Exchanges, bridges, staking, lending, stablecoins, oracles, pre-markets, launchpads.
Skipping all noise. Only looking for MONEY-extractable vulnerabilities.
"""
import tomllib
import logging
import time
import sys
from decimal import Decimal
from typing import Optional
from src.rpc import RpcClient
from src.types import TokenInfo, PoolInfo, Chain, Severity
from src.scanners.evm_scanner import EvmScanner
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.verifiers.runner import VerifierRunner
from src.verifiers.honeypot import HoneypotVerifier
from src.verifiers.exploit_simulator import SimulatedExploitVerifier
from src.verifiers.multi_step import MultiStepVerifier
from src.exploit_executor import ExploitExecutor
from src.signer import load_evm_private_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("whale")

CHAIN_MAP = {c.name.lower(): c for c in Chain}

# ============================================================
# WHALE TARGETS — only contracts that can hold significant $$
# ============================================================

WHALES = {
    "ethereum": {
        # === CEX Hot Wallets ===
        "exchange": [
            ("0x28C6c06298d514Db089934071355E5743bf21d60", "Binance 14"),
            ("0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549", "Binance 15"),
            ("0xDFd5293D8e347dFe59E90eFd55b2956a1343963d", "Binance 16"),
            ("0x56Eddb7aa87536c09CCc2793473599fD21A8b17F", "Binance 17"),
            ("0x9696f59E4d72E237BE84fFD425DCaD154Bf96976", "Binance 18"),
            ("0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8", "Binance 7"),
            ("0xF977814e90dA44bFA03b6295A0616a897441aceC", "Binance 8"),
            ("0x5a52E96BAcdaBb82fd05763E25335261B270Efcb", "Binance 20"),
            ("0x6262998Ced04146fA42253a5C0AF90CA02dfd2A3", "Crypto.com 1"),
            ("0x46340b20830761efd32832A74d7169B29FEB9758", "Crypto.com 2"),
            ("0x1151314c646Ce4E0eFD76d1aF4760aE66a2Fe30a", "Bitfinex 1"),
            ("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2", "Bitfinex 2"),
            ("0x876EabF105B2C82F2b5Ae2c5F62B1d7eD2149792", "Bitfinex 3"),
            ("0x77134cbC06cB00b66F4c7e623D5fdBF6777635EC", "Bitfinex 4"),
            ("0xE92d1A43df510F82C66382592a047d288f85226f", "Kraken 1"),
            ("0x2910543Af39abA0Cd09dBb2D50200b3E800A63D2", "Kraken 4"),
            ("0x0548F59fC3AfD22d6f27fd5bC81c5c3C3f1b0FB3", "Kraken 5"),
            ("0x66F820a414824B937427C57bc4BeD4D3f2A7ddAc", "Kraken 7"),
            ("0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367", "OUR SIGNER"),
        ],
        # === Bridges (largest ETH holders) ===
        "bridge": [
            ("0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a", "Arbitrum Bridge"),
            ("0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1", "Polygon Bridge"),
            ("0x3154Cf16ccdb4C6d922629664174b904d80F2C35", "Base Bridge"),
            ("0x49048044D57e1C92A77f79988d21Fa8fAF74E97e", "Optimism Bridge"),
            ("0x32400084C286CF3E17e7B677ea9583e60a000324", "zkSync Bridge"),
            ("0x3ee18B2214AFF97000D974cf647E7C347E8fa585", "Wormhole Bridge"),
            ("0x5a3e6A77ba2f983eC0d371eA3B475F8Bc0811AD5", "LayerZero Bridge"),
            ("0xa0C68C638235ee32657e8f720a23ceC1bFc77C77", "Polygon Bridge (L2)"),
            ("0xb8901acB165ed027E32754E0FFe830802919727f", "Hop Protocol Bridge"),
            ("0x3666f603Cc164936C1b87e207F36BEBa4AC5f18a", "Across Protocol Bridge"),
        ],
        # === Lending (deposited billions) ===
        "lending": [
            ("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "Aave V2 Lending"),
            ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "Aave V3 Lending"),
            ("0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "Compound Comptroller"),
            ("0xc3d688B66703497DAA19211EEdff47f25384cdc3", "Compound USDC"),
            ("0xA17581A9E3356d9A858b789D68B4d866e593aE94", "Compound WETH"),
            ("0x39AA39c021dfbaE8faC545936693aC917d5E7563", "Compound USDC v2"),
            ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH"),
            ("0xF63B34710400CAd3e044cFfDcAb00a0f32E33eCF", "Maker DssVat"),
            ("0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B", "Maker DssCdpManager"),
        ],
        # === Liquid Staking (billions in TVL) ===
        "staking": [
            ("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "Lido stETH"),
            ("0x17144556fd3424EDC8Fc8A4C940B2D04936d17eb", "Lido WithdrawalQueue"),
            ("0x1a8E3bF45e53Ci8f8eE6a14606B8aE1E8f5cA621", "Rocket Pool rETH"),
            ("0xDd3b91833c3D914039FaB3fd418D28e1924fFE9D", "Rocket Pool Storage"),
            ("0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2", "Lido NodeOperators"),
            ("0xf951E335afb289353dc249e82926178EaC7DEd78", "Swell swETH"),
            ("0x7122985656e38BDC0302Db86685bb972b145bD3C", "StakeWise sETH2"),
            ("0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38", "Stader ETHx"),
            ("0xac3E018457B222d93114458476f3E3416Abbe38F", "Frax sfrxETH"),
        ],
        # === Stablecoins ===
        "stablecoin": [
            ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC"),
            ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT"),
            ("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI"),
            ("0x853d955aCEf822Db058eb8505911ED77F175b99e", "FRAX"),
            ("0x8E870D67F660D95d5be530380D0eC0bd388289E1", "USDP"),
            ("0x056Fd409E1d7A124BD7017459dFEa2F387b6d5Cd", "GUSD"),
        ],
        # === Oracles (price manipulation targets) ===
        "oracle": [
            ("0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", "Chainlink ETH/USD"),
            ("0xEEA929fDB61bB2c8ad755B5BdFDdAfE7A7d46DC1", "Chainlink BTC/USD"),
            ("0x547a514d5e3769680Ce22B2361c10Ea13619e8a9", "Chainlink AAVE/USD"),
            ("0xCd627aA160A6fA45Eb793D19Ef54f5062F20f33f", "Chainlink LINK/USD"),
        ],
        # === DEX / Aggregators ===
        "dex": [
            ("0xE592427A0AEce92De3Edee1F18E0157C05861564", "Uniswap V3 Router"),
            ("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "Uniswap V3 Router 2"),
            ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "Uniswap V2 Router"),
            ("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "Uniswap Universal Router"),
            ("0x1111111254fb6c44bAC0beD2854e76F90643097d", "1inch Router V5"),
            ("0x1111111254EEB25477B68fb85Ed929f73A960582", "1inch Router V4"),
            ("0xDef1C0ded9bec7F1a1670819833240f027b25EfF", "0x Proxy"),
            ("0x881D40237659C251811CEC9c364ef91dC08D300C", "MetaMask Swap"),
            ("0x7bc06d232cfb1a3c8beCa9f49bFdaf1ce41a60d8", "Cowswap GPv2Settlement"),
        ],
        # === Governance / Treasury ===
        "governance": [
            ("0x1a9C8182C09F50C8318d769245beA52c32BE35BC", "Uniswap Timelock"),
            ("0x408ED6354d4973f66138C91495F2f2FCbd8724C3", "Uniswap Governor"),
            ("0xb8FFC3Cd6e7Cf5a098A1c92F48009765B24088Dc", "Aave Governance V2"),
            ("0xEC568fffba86c094cf06b22134B23074DFE2252c", "Aave Governance V3"),
            ("0x9a67F1940164d0318612b497E8e6038f902a00a4", "Gitcoin Treasury"),
            ("0xbC6DA0fe9aD5f3b0d58160288917AA56653660E9", "Arbitrum DAO Treasury"),
            ("0xf89d7b9c864f589bbF53a82105107622B35EaA40", "Optimism Treasury"),
        ],
        # === Launchpads / Pre-markets ===
        "launchpad": [
            ("0xDAFe0F28F65A55C6C91b7Bd0837E78dF9eDB29A8", "Whales Market"),
            ("0xc69A71478eeaDb45Bc12283a7F3c6F4B03F2e30E", "Aevo Pre-Market"),
            ("0x0000000000000000000000000000000000000000", "Ether.fi Launchpad"),
        ],
    },

    "polygon": {
        "exchange": [
            ("0x712754aC7D077C27E6D5c0656959A88d4cB172fB", "Binance Hot"),
        ],
        "bridge": [
            ("0xA0c68C638235ee32657e8f720a23ceC1bFc77C77", "Polygon Bridge ETH"),
            ("0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30", "Polygon Bridge Token"),
        ],
        "lending": [
            ("0x794a61358D6845594F94dc1DB02A252b5b4814aD", "Aave V3 Lending"),
            ("0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf", "Aave V3 Pool"),
            ("0x1bfD67037B42Cf73acF2047067bd4F2C47D9BfD6", "WBTC"),
            ("0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", "WETH"),
        ],
        "dex": [
            ("0xE592427A0AEce92De3Edee1F18E0157C05861564", "Uniswap V3 Router"),
            ("0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff", "QuickSwap Router"),
            ("0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "Sushi Router"),
        ],
        "stablecoin": [
            ("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "USDC"),
            ("0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "USDT"),
            ("0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", "DAI"),
        ],
        "oracle": [
            ("0xF9680D99D6C9589e2a93a78A04A279e509205945", "Chainlink ETH/USD"),
        ],
        "governance": [
            ("0xeE9C57e6C518b8650e5CDBbF42F78d68E0B546E9", "Polygon Treasury"),
        ],
    },

    "arbitrum": {
        "bridge": [
            ("0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a", "Arbitrum Bridge (L1)"),
            ("0x0000000000000000000000000000000000000064", "ArbSys"),
        ],
        "lending": [
            ("0x794a61358D6845594F94dc1DB02A252b5b4814aD", "Aave V3 Lending"),
        ],
        "dex": [
            ("0xE592427A0AEce92De3Edee1F18E0157C05861564", "Uniswap V3 Router"),
            ("0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "Sushi Router"),
            ("0x960ea3e3C7FB317332d990873d354E18d7645590", "GMX Router"),
        ],
        "stablecoin": [
            ("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USDC"),
            ("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "USDT"),
            ("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", "DAI"),
        ],
    },

    "base": {
        "bridge": [
            ("0x3154Cf16ccdb4C6d922629664174b904d80F2C35", "Base Bridge"),
            ("0x49048044D57e1C92A77f79988d21Fa8fAF74E97e", "Optimism Bridge"),
        ],
        "lending": [
            ("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", "Aave V3 Lending"),
        ],
        "dex": [
            ("0x2626664c2603336E57B271c5C0b26F421741e481", "Uniswap V3 Router"),
            ("0x6cDEd4B226EaDBE7D38AC8315512cD7C8BbAfD6B", "Aerodrome Router"),
        ],
        "stablecoin": [
            ("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC"),
        ],
    },
}


def get_balance(rpc, addr: str) -> float:
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        return int(str(raw), 16) / 1e18
    except Exception:
        return 0.0


def hunt_chain(chain_key: str, rpc_url: str, drain: bool = False):
    """Scan all whale targets on a chain. Only report CRITICAL+exploitable."""
    chain = CHAIN_MAP.get(chain_key)
    if not chain or chain_key not in WHALES:
        logger.warning("No whale data for %s", chain_key)
        return

    rpc = RpcClient(rpc_url, max_retries=5)
    signer = load_evm_private_key()
    executor = ExploitExecutor(signer=signer) if (drain and signer) else None

    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)

    logger.info("=" * 60)
    logger.info("WHALE HUNTER: %s (drain=%s)", chain_key.upper(), drain)
    logger.info("=" * 60)

    all_critical: list[tuple[str, str, float, str, float]] = []

    for category, targets in WHALES[chain_key].items():
        logger.info("--- %s (%d targets) ---", category.upper(), len(targets))
        for addr, name in targets:
            if addr == "0x0000000000000000000000000000000000000000":
                continue

            bal = get_balance(rpc, addr)
            if bal < 0.001:
                continue

            logger.info("  %s (%s): %.4f", addr[:12], name, bal)
            token = TokenInfo(address=addr, symbol=name[:12], chain=chain)
            pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))

            try:
                report = scanner.scan(token, pool)
            except Exception as e:
                logger.error("  Scan error: %s", e)
                continue

            criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
            if criticals:
                for f in criticals:
                    logger.warning("  ⚠️  CRITICAL: %s conf=%.2f | %s | %.4f ETH",
                                   f.check_name, f.confidence or 0, name, bal)
                    all_critical.append((addr, name, bal, f.check_name, f.confidence or 0))
            else:
                logger.debug("  Clean: %s", name)

    # Save critical hits
    if all_critical:
        with open(f"whale_critical_{chain_key}.txt", "w") as f:
            for addr, name, bal, check, conf in sorted(all_critical, key=lambda x: -x[2]):
                f.write(f"{addr} | {name} | {bal:.6f} | {check} | conf={conf:.2f}\n")
        logger.info("WHALE DONE: %d CRITICAL hits → whale_critical_%s.txt",
                     len(all_critical), chain_key)
    else:
        logger.info("WHALE DONE: 0 CRITICAL on %s", chain_key)


def main():
    if len(sys.argv) < 2:
        print("Usage: python whale_hunter.py <chain|all> [--drain]")
        return

    target = sys.argv[1].lower()
    drain = "--drain" in sys.argv

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    chains_to_hunt = list(WHALES.keys()) if target == "all" else [target]

    for chain_key in chains_to_hunt:
        rpc_url = config["rpc"].get(chain_key, "")
        if not rpc_url:
            logger.warning("No RPC for %s", chain_key)
            continue
        hunt_chain(chain_key, rpc_url, drain=drain)


if __name__ == "__main__":
    main()
