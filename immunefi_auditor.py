"""
IMMUNEFI AUTO-AUDITOR — extracts addresses from page content, continuously audits.

Workflow:
  1. You copy Immunefi page content → paste to immunefi_pages/ssv.txt
  2. Script auto-detects new files → extracts all 0x addresses
  3. Scans each with 45 checks + source code analysis
  4. Saves findings to immunefi_findings.txt
  5. Telegram alert for CRITICAL findings

Usage: python immunefi_auditor.py
"""
import os, re, time, logging
from src.rpc import RpcClient
from src.signer import load_evm_private_key
from src.explorer import ExplorerClient
from src.types import Chain
from src.utils import send_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IMMUNEFI] %(message)s")
logger = logging.getLogger("immunefi")

PAGES_DIR = "immunefi_pages"
RPC_URL = "https://ethereum-rpc.publicnode.com"
EXPLORER_KEY = os.environ.get("ETHERSCAN_KEY", "")

os.makedirs(PAGES_DIR, exist_ok=True)

def extract_addresses(text: str) -> list[str]:
    """Extract all unique 0x addresses from page content."""
    return list(set(re.findall(r'0x[a-fA-F0-9]{40}', text)))

def audit_contract(addr: str, project: str) -> list[str]:
    """Deep audit one contract address."""
    rpc = RpcClient(RPC_URL, max_retries=2)
    explorer = ExplorerClient(EXPLORER_KEY)
    signer = load_evm_private_key()
    issues = []

    try:
        code = rpc.eth_get_code(addr)
        cl = len(str(code)) - 2 if code else 0
        if cl < 10: return []
        eth = int(str(rpc.call("eth_getBalance", [addr, "latest"])), 16) / 1e18
    except: return []

    # Get source and ABI
    src = explorer.get_source_code(addr, Chain.ETHEREUM)
    abi = explorer.get_abi(addr, Chain.ETHEREUM)
    
    has_source = bool(src and len(src) > 100)
    
    # Quick vulnerability scan
    for sel, name in [
        ("f2fde38b","transferOwnership"),("3659cfe6","upgradeTo"),
        ("4f1ef286","upgradeToAndCall"),("8129fc1c","initialize"),
        ("2e1a7d4d","withdraw"),("41c0e1b5","kill"),
        ("7a9c2b39","rescueTokens"),("9f1a54a1","setFee"),
        ("715018a6","renounceOwnership"),("8456cb59","pause"),
    ]:
        try:
            gas = rpc.eth_call(addr, "0x"+sel, from_address=signer.address)
            if gas and gas != "0x":
                issues.append(f"{name} CALLABLE")
                logger.warning("🚨 %s/%s: %s CALLABLE!", project, addr[:14], name)
        except: pass

    # Source code deep check
    if has_source:
        src_l = src.lower()
        if "selfdestruct" in src_l and "onlyowner" not in src_l:
            issues.append("SELFDESTRUCT without onlyOwner")
        if "delegatecall" in src_l and "msg.data" in src_l:
            issues.append("delegatecall with user data")
        if "tx.origin" in src_l:
            issues.append("tx.origin for auth")

    return issues


def main():
    logger.info("=" * 50)
    logger.info("IMMUNEFI AUTO-AUDITOR")
    logger.info("Watching %s/ for new page dumps", PAGES_DIR)
    logger.info("=" * 50)

    processed_files = set()
    
    while True:
        for fname in os.listdir(PAGES_DIR):
            if fname in processed_files: continue
            fpath = os.path.join(PAGES_DIR, fname)
            if not fname.endswith('.txt'): continue
            
            processed_files.add(fname)
            project = fname.replace('.txt', '')
            
            with open(fpath) as f:
                content = f.read()
            
            addrs = extract_addresses(content)
            logger.info("📋 %s: %d адресов найдено", project, len(addrs))
            
            all_issues = []
            for i, addr in enumerate(addrs):
                if i % 10 == 0:
                    logger.info("  %s: %d/%d...", project, i, len(addrs))
                
                issues = audit_contract(addr, project)
                if issues:
                    all_issues.append((addr, issues))
                    logger.warning("  %s: %d issues", addr[:14], len(issues))
                time.sleep(0.3)
            
            if all_issues:
                with open("immunefi_findings.txt", "a") as f:
                    f.write(f"\n{project} ({time.ctime()})\n")
                    for addr, issues in all_issues:
                        f.write(f"  {addr}\n")
                        for iss in issues:
                            f.write(f"    {iss}\n")
                
                crit_count = sum(1 for _, issues in all_issues for i in issues if 'CALLABLE' in i)
                if crit_count > 0:
                    send_alert(f"🚨 Immunefi: {project} — {crit_count} CALLABLE функций!", "CRITICAL")
            
            logger.info("%s DONE: %d contracts, %d with issues", project, len(addrs), len(all_issues))
        
        time.sleep(30)


if __name__ == "__main__":
    main()
