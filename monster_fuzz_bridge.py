"""
MONSTER-FUZZ BRIDGE — auto-fuzzes every money contract the scanner finds.

Flow:
  Monster/ERC20 sweep finds contract with money
    → Bridge adds it to Foundry fuzz test
    → forge test runs 10k iterations
    → Telegram alert if invariant violated
    → Contract stays in continuous fuzz rotation

Usage: python monster_fuzz_bridge.py
"""
import re, os, time, subprocess, logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [BRIDGE] %(message)s")
logger = logging.getLogger("monster-fuzz")

FUZZ_DIR = Path("fuzz/foundry/test")
TEMPLATE_PATH = Path("fuzz/foundry/template.t.sol")
TEST_PATH = FUZZ_DIR / "MoneyContractFuzz.t.sol"
MIN_BALANCE_USD = 50  # only fuzz contracts with >$50

# Track already-fuzzed contracts
FUZZED_CONTRACTS: set[str] = set()
if Path("fuzzed_contracts.txt").exists():
    FUZZED_CONTRACTS = set(Path("fuzzed_contracts.txt").read_text().splitlines())

def extract_money_contracts():
    """Extract contract addresses from all scanner output files."""
    contracts = []
    
    # Scan all output files
    for pattern in ["critical_*.txt", "token_rich_*.txt", "full_erc20_hits.txt"]:
        for fpath in Path(".").glob(pattern):
            content = fpath.read_text()
            # Extract addresses + balances
            for line in content.split("\n"):
                # Match patterns like: "0x... | USDC | 784.00" or "0x... = 0.01 ETH"
                addr_match = re.search(r'(0x[a-fA-F0-9]{40})', line)
                if not addr_match: continue
                addr = addr_match.group(1)
                
                # Extract value
                value_match = re.search(r'\$?(\d+\.?\d*)\s*(ETH|USDC|USDT|DAI|WETH|MATIC)', line)
                if not value_match: continue
                value = float(value_match.group(1))
                
                contracts.append((addr, value, str(fpath)))
    
    return contracts

def inject_contracts_into_test(new_contracts: list[str]):
    """Add new contract addresses and their selectors to the Foundry test."""
    test_content = TEST_PATH.read_text() if TEST_PATH.exists() else TEMPLATE_PATH.read_text()
    
    # Find the "constant" section and add new addresses
    for i, addr in enumerate(new_contracts):
        var_name = f"FUZZ_{i}"
        # Add address constant
        insert_line = f"    address constant {var_name} = {addr};"
        if insert_line not in test_content:
            # Insert after last constant
            last_constant = test_content.rfind("address constant ")
            end_of_line = test_content.find("\n", last_constant) + 1
            test_content = test_content[:end_of_line] + insert_line + "\n" + test_content[end_of_line:]
        
        FUZZED_CONTRACTS.add(addr)
    
    TEST_PATH.write_text(test_content)
    Path("fuzzed_contracts.txt").write_text("\n".join(FUZZED_CONTRACTS))

def run_fuzz():
    """Run Foundry fuzz tests on the fork."""
    try:
        result = subprocess.run(
            ["forge", "test", "--fork-url", "mainnet", "--fuzz-runs", "10000", "-v"],
            cwd="fuzz/foundry",
            capture_output=True, text=True, timeout=600
        )
        
        # Check for invariant violations
        if "FAIL" in result.stdout or "FAIL" in result.stderr:
            logger.warning("🚨 FUZZ VIOLATION FOUND!")
            logger.warning(result.stdout[-500:])
            
            # Save violation for analysis
            Path("fuzz_violations.txt").write_text(
                Path("fuzz_violations.txt").read_text() +
                f"\n{time.ctime()}\n{result.stdout}\n"
            )
            
            from src.utils import send_alert
            send_alert(f"🚨 FUZZER: Invariant violation detected!\nCheck fuzz_violations.txt", "CRITICAL")
            return True
    except subprocess.TimeoutExpired:
        logger.error("Fuzz timeout")
    except Exception as e:
        logger.error("Fuzz error: %s", e)
    return False

def main():
    if not TEST_PATH.exists():
        logger.error("No test file at %s", TEST_PATH)
        logger.error("Run: cd fuzz/foundry && forge init")
        return
    
    logger.info("=" * 50)
    logger.info("MONSTER-FUZZ BRIDGE")
    logger.info("Watching for money contracts → auto-fuzz")
    logger.info("=" * 50)
    
    while True:
        # Find new money contracts
        contracts = extract_money_contracts()
        new_contracts = [addr for addr, val, src in contracts 
                        if addr not in FUZZED_CONTRACTS and val > MIN_BALANCE_USD]
        
        if new_contracts:
            logger.info("Found %d new money contracts", len(new_contracts))
            for addr, val, src in new_contracts:
                logger.info("  %s — $%.0f from %s", addr[:14], val, src)
            
            inject_contracts_into_test(new_contracts)
            
            # Run fuzz
            violation = run_fuzz()
            if violation:
                logger.warning("Violation found! Check fuzz_violations.txt")
        
        logger.info("Sleeping 60s...")
        time.sleep(60)

if __name__ == "__main__":
    main()
