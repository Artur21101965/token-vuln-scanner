import logging, sys, json, traceback
from decimal import Decimal
from src.rpc import RpcClient
from src.data import DataCollector
from src.explorer import ExplorerClient
from src.scanners.evm_scanner import EvmScanner
from src.sources.blockscout import BlockscoutRecentSource
from src.types import Chain, ContractTarget, TokenInfo, PoolInfo, Severity
from src.exploit_format import format_exploit_plan

logging.basicConfig(stream=sys.stderr, level=logging.ERROR)

CHAIN = Chain.BASE
RPC_URL = "https://mainnet.base.org"
BLOCKSCOUT_URL = "https://base.blockscout.com/api/v2"

rpc = RpcClient(RPC_URL)
explorer = ExplorerClient()
data = DataCollector(rpc, explorer)
scanner = EvmScanner(data_collector=data, rpc=rpc)

source = BlockscoutRecentSource(max_pages=2)
targets = source.fetch(CHAIN)
targets = targets[:20]

print(f"Fetched {len(targets)} contracts from Blockscout (Base)")
print()

results = []

for i, target in enumerate(targets):
    addr = target.address
    print(f"[{i+1}/{len(targets)}] Checking {addr[:10]}... ", end="", flush=True)
    try:
        bal_hex = rpc.eth_get_balance(addr)
        bal = int(bal_hex, 16) if bal_hex and bal_hex != "0x" else 0
        bal_eth = bal / 10**18
    except Exception as e:
        print(f"balance error: {e}")
        continue

    if bal == 0:
        print(f"balance=0, skip")
        continue

    print(f"balance={bal_eth:.6f} ETH, scanning... ", end="", flush=True)
    try:
        token_info = TokenInfo(address=addr, symbol=addr[:10], chain=CHAIN)
        pool_info = PoolInfo(address="", dex="direct", liquidity_usd=Decimal("0"))
        report = scanner.scan(token_info, pool_info)
    except Exception as e:
        print(f"scan error: {e}")
        continue

    criticals = [f for f in report.findings if f.severity == Severity.CRITICAL]
    if not criticals:
        print(f"no critical (found {len(report.findings)} non-critical)")
        continue

    print(f"CRITICAL x{len(criticals)}!")
    for finding in criticals:
        plan = format_exploit_plan(finding, addr, CHAIN, bal)
        print()
        print(plan)
        results.append({
            "chain": "base",
            "address": addr,
            "balance_eth": bal_eth,
            "check": finding.check_name,
            "finding": finding,
            "plan": plan,
        })

print()
print("=" * 60)
print(f"  SCAN COMPLETE — {len(targets)} contracts checked, {len(results)} with critical findings")
print("=" * 60)
for r in results:
    print(f"  {r['address'][:10]} — {r['check']} — {r['balance_eth']:.4f} ETH")
