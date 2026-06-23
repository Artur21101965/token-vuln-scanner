"""Dashboard with tabs, real-time stats, process details, findings feed, settings."""
import os, glob, json, subprocess, time, threading
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
import sqlite3
import tomllib as _tomllib

TEMPLATE_DIR = Path(__file__).parent / "templates"
app = FastAPI(title="Monster Exploit Scanner")
_jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

# Запускаем PNL трекер при старте дашборда
_pnl_started = False

CHAIN_NAMES = {"ethereum": "Ethereum", "polygon": "Polygon", "arbitrum": "Arbitrum",
               "base": "Base", "bsc": "BSC", "optimism": "Optimism", "avalanche": "Avalanche",
               "linea": "Linea", "scroll": "Scroll", "zksync": "zkSync"}

PROC_INFO = {
    "Monster Scanner":  ("Сканер контрактов", "45 проверок, 8 слоёв, 9 цепей"),
    "Predator":         ("Мемпул + свежие деплои", "WebSocket мониторинг"),
    "Drain Scanner":    ("Фоновый дренаж", "10 цепей, Blockscout"),
    "Solana Predator":  ("Solana монитор", "RugCheck + GoPlus"),
    "Leaked Key Hunter":("Охота за ключами", "17 источников утечек"),
    "GitHub Scout":     ("Pre-release аудит", "Solidity репо, каждые 3ч"),
    "DefiLlama Auditor":("Аудит протоколов", "Топ-50, каждые 6ч"),
    "CREATE2 Hunter":   ("Metamorphic контракты", "Front-run CREATE2"),
    "Deploy Frontrunner":("Фронтран деплоя", "Мемпул, перехват"),
    "Governance Sniper":("DAO монитор", "Proposals + Timelock"),
    "Storage Fisher":   ("Storage fishing", "Ключи в слотах"),
    "Testnet Farmer":   ("Тестнет-фермер", "Monad, Berachain"),
    "Protocol Hunter":  ("Новые протоколы", "Деплой + аудит"),
    "Key Monitor":      ("Монитор ключей", "11k+ ключей, 30 мин"),
    "ENS Sniper":       ("ENS домены", "1751 имён, eth_call 🆕"),
    "V4 Hook Hunter":   ("Uniswap V4 хуки", "Ждёт запуска V4 🆕"),
    "Launchpad Vulture":("Вестинг / Локи", "Unicrypt, Team Finance 🆕"),
    "Flash Auto":       ("Flash Loan атаки", "Polygon, 30 сек цикл"),
}

ALL_SCRIPTS = [
    ("monster_scanner.py", "Monster Scanner"),
    ("predator.py", "Predator"),
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
    ("ens_sniper.py", "ENS Sniper"),
    ("v4_hook_hunter.py", "V4 Hook Hunter"),
    ("launchpad_vulture.py", "Launchpad Vulture"),
    ("flash_auto.py", "Flash Auto"),
    ("run_dashboard.py", "Дашборд"),
]

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config.toml")


def _get_processes():
    result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    lines = result.stdout.split("\n")
    processes = []

    for script, name in ALL_SCRIPTS:
        desc_short, desc_long = PROC_INFO.get(name, ("", ""))
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
    stats = {
        "processes_alive": 0,
        "processes_total": 0,
        "findings_db": 0,
        "findings_critical": 0,
        "findings_txt": 0,
        "keys_monitored": 0,
        "contracts_fuzzed": 0,
        "contracts_total": 0,
        "ens_expiring": 0,
    }

    procs = _get_processes()
    stats["processes_alive"] = sum(1 for p in procs if p["alive"])
    stats["processes_total"] = len(procs)

    try:
        db = sqlite3.connect("scanner.db")
        stats["findings_db"] = db.execute("SELECT COUNT(*) FROM findings_log").fetchone()[0]
        stats["findings_critical"] = db.execute("SELECT COUNT(*) FROM findings_log WHERE severity='CRITICAL'").fetchone()[0]
        stats["contracts_total"] = db.execute("SELECT COUNT(*) FROM contract_targets").fetchone()[0]
        db.close()
    except Exception:
        pass

    for pat in ["critical_*.txt", "token_rich_*.txt", "leaked_keys_found.txt", "github_scout_findings.txt"]:
        for fp in glob.glob(pat):
            try:
                with open(fp) as f:
                    stats["findings_txt"] += len(f.readlines())
            except Exception:
                pass

    try:
        with open("all_leaked_private_keys.txt") as f:
            stats["keys_monitored"] = len(f.readlines())
    except Exception:
        pass

    try:
        with open("fuzzed_contracts.txt") as f:
            stats["contracts_fuzzed"] = len(f.readlines())
    except Exception:
        pass

    try:
        with open("ens_expiring.txt") as f:
            stats["ens_expiring"] = len(f.readlines())
    except Exception:
        pass

    return stats


def _get_recent_findings(n=20):
    findings = []
    VERDICTS = {
        "bytecode_selfdestruct": "🔴 Ложное — SELFDESTRUCT недостижим",
        "public_ownership_transfer": "🔴 Ложное — только owner может",
        "unprotected_upgrade": "🔴 Ложное — за governance/timelock",
        "delegatecall_injection": "🟡 Прокси — стандартный паттерн",
        "opcode_delegatecall": "🟡 Прокси — стандартный паттерн",
        "initialize() can be called": "🔴 Ложное — OpenZeppelin initializer",
        "low-level call without check": "🟠 Реальный паттерн — нужна проверка",
    }
    
    for pat in ["critical_*.txt", "token_rich_*.txt", "github_scout_findings.txt"]:
        for fp in sorted(glob.glob(pat)):
            try:
                with open(fp) as f:
                    lines = f.readlines()
                for line in lines[-n:]:
                    line = line.strip()
                    if not line or len(line) < 10:
                        continue
                    verdict = ""
                    if "github" not in fp.lower() and "critical" not in fp.lower():
                        for key, val in VERDICTS.items():
                            if key.lower() in line.lower():
                                verdict = val
                                break
                    findings.append({
                        "source": fp.replace(".txt", "").replace("_", " "),
                        "text": line[:200],
                        "verdict": verdict,
                    })
            except Exception:
                pass
    return findings[-n:]


def _get_gas():
    gas_info = []
    try:
        from src.rpc import RpcClient
        addr = "0xaA83AD23Fc48a72e4810cc26E7D58E41a1D1eC5A"
        for chain, url, ticker in [
            ("Polygon", "https://polygon-bor.publicnode.com", "MATIC"),
            ("Ethereum", "https://ethereum-rpc.publicnode.com", "ETH"),
            ("Solana", None, "SOL"),
        ]:
            try:
                if chain == "Solana":
                    import urllib.request, json as j
                    payload = j.dumps({"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": ["2Vk4a5GMsU8vMRqdS4MJTRPS34gRgkbxiyWrQtKeZjho"]}).encode()
                    req = urllib.request.Request("https://api.mainnet-beta.solana.com", payload, {"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        bal = j.loads(resp.read())["result"]["value"] / 1e9
                else:
                    rpc = RpcClient(url, max_retries=1)
                    raw = rpc.call("eth_getBalance", [addr, "latest"])
                    bal = int(str(raw), 16) / 1e18
                gas_info.append({"chain": chain, "balance": f"{bal:.4f} {ticker}", "ok": bal > 0.001})
            except Exception:
                gas_info.append({"chain": chain, "balance": "—", "ok": False})

        try:
            rpc = RpcClient("https://polygon-bor.publicnode.com", max_retries=1)
            code = rpc.eth_get_code("0x0B8579e155C432fF36C6C2eDF87B95F0B8DFF170")
            flash_deployed = len(str(code)) > 100 if code else False
            gas_info.append({"chain": "Flash Loan", "balance": "Активен" if flash_deployed else "Нет", "ok": flash_deployed})
        except Exception:
            pass
    except Exception:
        pass
    return gas_info


def _load_config():
    """Загружает config.toml."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return f.read()
    return ""


def _read_config_toml():
    """Читает конфиг как dict."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "rb") as f:
            return _tomllib.load(f)
    return {}


# ---- ROUTES ----

@app.on_event("startup")
async def startup():
    global _pnl_started
    if not _pnl_started:
        try:
            from src.pnl_tracker import start_background
            start_background()
            _pnl_started = True
        except Exception:
            pass


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    processes = _get_processes()
    stats = _get_stats()
    findings = _get_recent_findings(20)
    gas = _get_gas()
    config_raw = _load_config()

    tpl = _jinja_env.get_template("dashboard.html")
    return HTMLResponse(tpl.render(
        now=datetime.now().strftime("%H:%M:%S"),
        processes=processes,
        stats=stats,
        findings=findings,
        gas=gas,
        chain_names=CHAIN_NAMES,
        config_raw=config_raw,
    ))


@app.get("/api/stats")
async def api_stats():
    return JSONResponse(_get_stats())


@app.get("/api/processes")
async def api_processes():
    return JSONResponse([{
        "name": p["name"], "alive": p["alive"], "count": p["count"],
        "desc": p["desc_short"], "instances": [
            {"pid": i["pid"], "chain": i["chain"]} for i in p["instances"]
        ]
    } for p in _get_processes()])


@app.get("/api/findings")
async def api_findings(n: int = 20):
    return JSONResponse(_get_recent_findings(n))


@app.get("/api/gas")
async def api_gas():
    return JSONResponse(_get_gas())


@app.get("/api/config")
async def api_get_config():
    config = _read_config_toml()
    return JSONResponse({
        "rpc": config.get("rpc", {}),
        "explorer": config.get("explorer", {}),
        "telegram": config.get("telegram", {}),
        "tor": config.get("tor", {}),
        "monitor": config.get("monitor", {}),
        "analyzer": config.get("analyzer", {}),
        "wallet": config.get("wallet", {}),
        "raw": _load_config(),
    })


@app.post("/api/config/save")
async def api_save_config(raw: str = Form("")):
    try:
        with open(CONFIG_PATH, "w") as f:
            f.write(raw)
        return JSONResponse({"ok": True, "message": "Конфиг сохранён"})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=400)


@app.post("/api/process/restart")
async def api_restart_process(script: str = Form("")):
    """Перезапускает процесс (kill + start)."""
    if not script:
        return JSONResponse({"ok": False, "message": "Не указан скрипт"}, status_code=400)
    
    # Kill existing
    result = subprocess.run(["pkill", "-f", script], capture_output=True, text=True)
    time.sleep(1)

    # Start new
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_file = f"logs/{script.replace('.py', '')}.log"
    os.makedirs(os.path.join(base_dir, "logs"), exist_ok=True)

    try:
        subprocess.Popen(
            ["python", script],
            cwd=base_dir,
            stdout=open(os.path.join(base_dir, log_file), "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return JSONResponse({"ok": True, "message": f"{script} перезапущен"})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.get("/api/pnl")
async def api_pnl():
    try:
        from src.pnl_tracker import get_snapshot
        snap = get_snapshot()
        start = snap.get("start_usd", 0)
        current = snap.get("current_usd", 0)
        delta = round(current - start, 2)
        return JSONResponse({
            "start_usd": start,
            "current_usd": current,
            "delta_usd": delta,
            "is_profitable": delta >= -0.01,  # допускаем погрешность
            "balances": snap.get("current_balances", {}),
            "gas_total": snap.get("total_gas_spent", 0),
            "drained_total": snap.get("total_drained_usd", 0),
            "flash_profit": snap.get("flash_profit_usd", 0),
            "flash_attempts": snap.get("flash_attempts", 0),
            "drain_attempts": snap.get("drain_attempts", 0),
            "last_update": snap.get("last_update", ""),
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
