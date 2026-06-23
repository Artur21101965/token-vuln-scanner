"""Dashboard with tabs, real-time stats, process details, findings feed."""
import os, glob, json, subprocess, time
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader
import sqlite3

TEMPLATE_DIR = Path(__file__).parent / "templates"
app = FastAPI(title="Monster Exploit Scanner")
_jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

CHAIN_NAMES = {"ethereum": "Ethereum", "polygon": "Polygon", "arbitrum": "Arbitrum",
               "base": "Base", "bsc": "BSC", "optimism": "Optimism", "avalanche": "Avalanche",
               "linea": "Linea", "scroll": "Scroll", "zksync": "zkSync"}

# Process descriptions
PROC_INFO = {
    "Monster": ("Сканер контрактов", "45 проверок, 8 слоёв поиска, 9 цепей"),
    "PREDATOR": ("Мемпул + свежие деплои", "WebSocket мониторинг новых контрактов"),
    "Drain Scanner": ("Фоновый дренажный сканер", "10 цепей, Blockscout, auto-drain"),
    "Solana Predator": ("Solana монитор", "RugCheck + GoPlus, новые токены"),
    "Leaked Key Hunter": ("Охотник за ключами", "GitHub, Gists, Pastebin, 13 источников"),
    "GitHub Scout": ("Pre-release аудит", "Новые Solidity репо каждые 3ч"),
    "DefiLlama Auditor": ("Аудит протоколов", "Топ-50 протоколов каждые 6ч"),
    "CREATE2 Hunter": ("Metamorphic контракты", "Front-run деплоя через CREATE2"),
    "Deploy Frontrunner": ("Фронтран деплоя", "Мемпул, перехват конструктора"),
    "Governance Sniper": ("Governance sniper", "Мониторинг DAO proposals"),
    "Storage Fisher": ("Storage fishing", "Поиск ключей в слотах контрактов"),
    "Testnet Farmer": ("Тестнет-фермер", "Monad, Berachain авто-фарминг"),
    "Protocol Hunter": ("Охотник протоколов", "Realtime деплой + мгновенный аудит"),
    "Key Monitor": ("Монитор ключей", "Проверка баланса каждые 30 мин"),
}


def _get_processes():
    result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    lines = result.stdout.split("\n")
    processes = []

    all_scripts = [(s, n, *PROC_INFO.get(n, ("", "")))
                   for s, n in [("predator.py", "PREDATOR"),
                                ("monster_scanner.py", "Monster"),
                                ("run_drain_scanner.py", "Drain Scanner"),
                                ("solana_predator.py", "Solana Predator"),
                                ("leaked_key_hunter.py", "Leaked Key Hunter"),
                                ("github_scout.py", "GitHub Scout"),
                                ("defillama_auditor.py", "DefiLlama Auditor"),
                                ("create2_hunter.py", "CREATE2 Hunter"),
                                ("deploy_frontrunner.py", "Deploy Frontrunner"),
                                ("governance_sniper.py", "Governance Sniper"),
                                ("storage_fisher.py", "Storage Fisher"),
                                ("testnet_farmer.py", "Testnet Farmer"),
                                ("protocol_hunter.py", "Protocol Hunter"),
                                ("key_monitor.py", "Key Monitor"),
                                ("run_dashboard.py", "Дашборд")]]

    for script, name, desc_short, desc_long in all_scripts:
        instances = []
        for line in lines:
            if script in line and "grep" not in line:
                parts = line.split()
                pid = parts[1] if len(parts) > 1 else ""
                chain = ""
                for p in parts[11:]:
                    if p.lower() in CHAIN_NAMES:
                        chain = CHAIN_NAMES[p.lower()]
                        break
                instances.append({"pid": pid, "chain": chain or "все"})
        processes.append({
            "name": name, "script": script,
            "alive": len(instances) > 0,
            "count": len(instances),
            "instances": instances,
            "desc_short": desc_short,
            "desc_long": desc_long,
        })

    return processes


def _get_stats():
    total = 0
    critical = 0
    try:
        db = sqlite3.connect("scanner.db")
        total = db.execute("SELECT COUNT(*) FROM findings_log").fetchone()[0]
        critical = db.execute("SELECT COUNT(*) FROM findings_log WHERE severity='CRITICAL'").fetchone()[0]
        db.close()
    except:
        pass

    # Count findings in text files
    txt_lines = 0
    for pat in ["critical_*.txt", "token_rich_*.txt", "leaked_keys_found.txt", "github_scout_findings.txt"]:
        for fp in glob.glob(pat):
            try:
                with open(fp) as f:
                    txt_lines += len(f.readlines())
            except:
                pass

    # Count keys being monitored
    keys = 0
    try:
        with open("all_leaked_private_keys.txt") as f:
            keys = len(f.readlines())
    except:
        pass

    # Count fuzzed contracts
    fuzzed = 0
    try:
        with open("fuzzed_contracts.txt") as f:
            fuzzed = len(f.readlines())
    except:
        pass

    return {
        "processes_alive": sum(1 for p in _get_processes() if p["alive"]),
        "processes_total": len(_get_processes()),
        "findings_db": total,
        "findings_critical": critical,
        "findings_txt": txt_lines,
        "keys_monitored": keys,
        "contracts_fuzzed": fuzzed,
    }


def _get_recent_findings(n=10):
    findings = []
    VERDICTS = {
        "bytecode_selfdestruct": "🔴 Ложное — SELFDESTRUCT недостижим",
        "public_ownership_transfer": "🔴 Ложное — только owner может",
        "unprotected_upgrade": "🔴 Ложное — за governance/timelock",
        "delegatecall_injection": "🟡 Прокси — стандартный паттерн",
        "opcode_delegatecall": "🟡 Прокси — стандартный паттерн",
        "initialize() can be called": "🔴 Ложное — OpenZeppelin initializer защищает",
        "low-level call without check": "🟠 Реальный паттерн — нужна проверка",
        "WETH": "ℹ️ WETH на балансе — проверить drain",
        "USDC": "ℹ️ USDC на балансе — проверить drain",
        "USDT": "ℹ️ USDT на балансе — проверить drain",
    }
    
    for pat in ["critical_*.txt", "token_rich_*.txt", "github_scout_findings.txt"]:
        for fp in sorted(glob.glob(pat)):
            try:
                with open(fp) as f:
                    lines = f.readlines()
                for line in lines[-n:]:
                    line = line.strip()
                    if not line or len(line) < 10: continue
                    
                    # Apply verdict (only for non-github, non-timestamp findings)
                    verdict = ""
                    if "github" not in fp.lower() and "critical" not in fp.lower():
                        for key, val in VERDICTS.items():
                            if key.lower() in line.lower():
                                verdict = val
                                break
                    elif "github" in fp.lower():
                        if "initialize() can be called" in line.lower():
                            verdict = "🔴 Ложное — OpenZeppelin initializer"
                        elif "low-level call without check" in line.lower():
                            verdict = "🟠 Реальный — нужна проверка при деплое"
                    
                    findings.append({
                        "source": fp.replace(".txt", "").replace("_", " "),
                        "text": line[:200],
                        "verdict": verdict,
                    })
            except:
                pass
    return findings[-n:]


def _get_gas():
    gas_info = []
    try:
        from src.rpc import RpcClient
        addr = "0xaA83AD23Fc48a72e4810cc26E7D58E41a1D1eC5A"
        for chain, url in [("Polygon", "https://polygon-bor.publicnode.com"),
                           ("Ethereum", "https://ethereum-rpc.publicnode.com")]:
            try:
                rpc = RpcClient(url, max_retries=1)
                raw = rpc.call("eth_getBalance", [addr, "latest"])
                bal = int(str(raw), 16) / 1e18
                ticker = "MATIC" if chain == "Polygon" else "ETH"
                gas_info.append({"chain": chain, "balance": f"{bal:.4f} {ticker}", "ok": bal > 0.001})
            except:
                gas_info.append({"chain": chain, "balance": "—", "ok": False})
        # Flash loan contract
        try:
            rpc = RpcClient("https://polygon-bor.publicnode.com", max_retries=1)
            code = rpc.eth_get_code("0x0B8579e155C432fF36C6C2eDF87B95F0B8DFF170")
            flash_deployed = len(str(code)) > 100 if code else False
            gas_info.append({"chain": "Flash Loan", "balance": "✅ Активен" if flash_deployed else "❌", "ok": flash_deployed})
        except:
            pass
    except:
        pass
    return gas_info


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    processes = _get_processes()
    stats = _get_stats()
    findings = _get_recent_findings(20)
    gas = _get_gas()

    tpl = _jinja_env.get_template("dashboard.html")
    return HTMLResponse(tpl.render(
        now=datetime.now().strftime("%H:%M:%S"),
        processes=processes,
        stats=stats,
        findings=findings,
        gas=gas,
        chain_names=CHAIN_NAMES,
    ))


@app.get("/api/stats")
async def api_stats():
    return JSONResponse(_get_stats())


@app.get("/api/processes")
async def api_processes():
    return JSONResponse([{
        "name": p["name"], "alive": p["alive"], "count": p["count"],
        "desc": p["desc_short"]
    } for p in _get_processes()])
