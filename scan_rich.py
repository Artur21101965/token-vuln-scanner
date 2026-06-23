"""Scan contracts with confirmed MATIC balance for vulnerabilities."""
import tomllib
import logging
from decimal import Decimal
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
from src.signer import load_evm_private_key, get_receive_address
from src.notifier.telegram import TelegramNotifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("scan-rich")

CHAIN_MAP = {"polygon": Chain.POLYGON}

def get_balance(rpc, addr):
    try:
        raw = rpc.call("eth_getBalance", [addr, "latest"])
        if isinstance(raw, dict):
            raw = raw.get("result", "0x0")
        return int(str(raw), 16) / 1e18 if raw else 0.0
    except:
        return 0.0

def main():
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    
    rpc = RpcClient(config["rpc"]["polygon"])
    chain = Chain.POLYGON
    
    signer = load_evm_private_key()
    telegram_cfg = config.get("telegram", {})
    telegram = TelegramNotifier(telegram_cfg.get("bot_token",""), telegram_cfg.get("chat_id","")) if telegram_cfg.get("bot_token") else None
    executor = ExploitExecutor(signer, telegram=telegram) if signer else None
    
    explorer = ExplorerClient()
    data = DataCollector(rpc=rpc, explorer=explorer)
    verifier_runner = VerifierRunner(verifiers=[
        HoneypotVerifier(), SimulatedExploitVerifier(), MultiStepVerifier(),
    ])
    scanner = EvmScanner(data_collector=data, rpc=rpc, verifier_runner=verifier_runner, executor=executor)
    
    targets = [
        ("0x48d5b60f51d5863d32f202dfd873ae50ea14ff6b", 0.218987),
        ("0xcbe7c3c951340cf5caaccd404315db68f0f731da", 65.526182),
        ("0xe69b6f0338e1f3785048598e597887ed9a153626", 1.000000),
    ]
    
    receive = get_receive_address(chain) or signer.address if signer else "?"
    initial_bal = get_balance(rpc, signer.address) if signer else 0
    logger.info("Signer: %s | Balance: %.6f | Receive: %s", signer.address if signer else "N/A", initial_bal, receive)
    
    for addr, known_bal in targets:
        bal = get_balance(rpc, addr)
        logger.info("=" * 60)
        logger.info("Scanning %s (%.4f MATIC)", addr, bal)
        
        if bal < 0.001:
            logger.info("  SKIP — balance too low")
            continue
        
        token = TokenInfo(address=addr, symbol=addr[:10], chain=chain)
        pool = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))
        
        try:
            report = scanner.scan(token, pool)
        except Exception as e:
            logger.error("  Scan failed: %s", e)
            continue
        
        criticals = [f for f in report.findings if f.severity.name == "CRITICAL"]
        highs = [f for f in report.findings if f.severity.name == "HIGH"]
        
        logger.info("  Findings: %d CRITICAL, %d HIGH, %d total",
                     len(criticals), len(highs), len(report.findings))
        
        for f in criticals:
            can_ex = executor and executor.can_execute(f)
            logger.info("  >> %s conf=%.2f can_execute=%s", f.check_name, f.confidence or 0, can_ex)
        
        if not criticals and not highs:
            logger.info("  Nothing interesting")
    
    final_bal = get_balance(rpc, signer.address) if signer else 0
    logger.info("Signer: %.6f → %.6f", initial_bal, final_bal)

if __name__ == "__main__":
    main()
