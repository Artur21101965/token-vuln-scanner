"""Dashboard 3.0 — WebSocket live updates, log viewer, mobile, PNL chart."""
import os, glob, json, subprocess, time, threading, asyncio
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Request, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from jinja2 import Environment, FileSystemLoader
import sqlite3
import tomllib as _tomllib

TEMPLATE_DIR = Path(__file__).parent / "templates"
app = FastAPI(title="Monster Exploit Scanner")
_jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

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
    "ENS Sniper":       ("ENS домены", "1751 имён, eth_call"),
    "V4 Hook Hunter":   ("Uniswap V4 хуки", "Ждёт запуска V4"),
    "Launchpad Vulture":("Вестинг / Локи", "Unicrypt, Team Finance"),
    "Flash Auto":       ("Flash Loan атаки", "Polygon, 30 сек цикл"),
}

ALL_SCRIPTS = [
    ("monster_scanner.py", "Monster Scanner"), ("predator.py", "Predator"),
    ("run_drain_scanner.py", "Drain Scanner"), ("solana_predator.py", "Solana Predator"),
    ("leaked_key_hunter.py", "Leaked Key Hunter"), ("github_scout.py", "GitHub Scout"),
    ("defillama_auditor.py", "DefiLlama Auditor"), ("create2_hunter.py", "CREATE2 Hunter"),
    ("deploy_frontrunner.py", "Deploy Frontrunner"), ("governance_sniper.py", "Governance Sniper"),
    ("storage_fisher.py", "Storage Fisher"), ("testnet_farmer.py", "Testnet Farmer"),
    ("protocol_hunter.py", "Protocol Hunter"), ("key_monitor.py", "Key Monitor"),
    ("ens_sniper.py", "ENS Sniper"), ("v4_hook_hunter.py", "V4 Hook Hunter"),
    ("launchpad_vulture.py", "Launchpad Vulture"), ("flash_auto.py", "Flash Auto"),
    ("run_dashboard.py", "Дашборд"),
]

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config.toml")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WS_CLIENTS: list[WebSocket] = []


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
                cpu = parts[2] if len(parts) > 2 else ""
                chain = ""
                for p in parts[11:]:
                    if p.lower() in CHAIN_NAMES:
                        chain = CHAIN_NAMES[p.lower()]
                        break
                instances.append({"pid": pid, "chain": chain or "все", "cpu": cpu})
        processes.append({
            "name": name, "script": script,
            "alive": len(instances) > 0, "count": len(instances),
            "instances": instances, "desc_short": desc_short, "desc_long": desc_long,
        })
    return processes


def _get_stats():
    stats = {"processes_alive": 0, "processes_total": 0, "findings_db": 0,
             "findings_critical": 0, "findings_txt": 0, "keys_monitored": 0,
             "contracts_fuzzed": 0, "contracts_total": 0, "ens_expiring": 0}
    procs = _get_processes()
    stats["processes_alive"] = sum(1 for p in procs if p["alive"])
    stats["processes_total"] = len(procs)
    try:
        db = sqlite3.connect("scanner.db")
        stats["findings_db"] = db.execute("SELECT COUNT(*) FROM findings_log").fetchone()[0]
        stats["contracts_total"] = db.execute("SELECT COUNT(*) FROM contract_targets").fetchone()[0]
        db.close()
    except: pass
    for pat in ["critical_*.txt", "token_rich_*.txt"]:
        for fp in glob.glob(pat):
            try:
                with open(fp) as f: stats["findings_txt"] += len(f.readlines())
            except: pass
    for fp, key in [("all_leaked_private_keys.txt", "keys_monitored"),
                     ("ens_expiring.txt", "ens_expiring")]:
        try:
            with open(fp) as f: stats[key] = len(f.readlines())
        except: pass
    return stats


def _get_recent_findings(n=20):
    findings = []
    for pat in ["critical_*.txt", "token_rich_*.txt"]:
        for fp in sorted(glob.glob(pat)):
            try:
                with open(fp) as f: lines = f.readlines()
                for line in lines[-n:]:
                    line = line.strip()
                    if line and len(line) >= 10:
                        findings.append({"source": fp.replace(".txt", "").replace("_", " "), "text": line[:200], "ts": ""})
            except: pass
    return findings[-n:]


def _get_gas():
    gas_info = []
    try:
        from src.rpc import RpcClient
        for chain, url, ticker in [("Polygon", "https://polygon-bor.publicnode.com", "MATIC"),
                                     ("Ethereum", "https://ethereum-rpc.publicnode.com", "ETH")]:
            try:
                rpc = RpcClient(url, max_retries=1)
                raw = rpc.call("eth_getBalance", ["0xaA83AD23Fc48a72e4810cc26E7D58E41a1D1eC5A", "latest"])
                bal = int(str(raw), 16) / 1e18
                gas_info.append({"chain": chain, "balance": f"{bal:.4f} {ticker}", "ok": bal > 0.001})
                rpc.close()
            except: gas_info.append({"chain": chain, "balance": "—", "ok": False})
    except: pass
    return gas_info


def _read_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f: return f.read()
    return ""


def _get_log_tail(script: str, lines: int = 50) -> str:
    """Читает последние строки лога процесса."""
    log_path = os.path.join(BASE_DIR, "logs", script.replace(".py", ".log"))
    if not os.path.exists(log_path):
        return f"[лог не найден: {log_path}]"
    try:
        with open(log_path) as f:
            all_lines = f.readlines()
        return "".join(all_lines[-lines:])
    except: return "[ошибка чтения]"


# === ROUTES ===

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(_jinja_env.get_template("dashboard.html").render(
        now=datetime.now().strftime("%H:%M:%S"),
        processes=_get_processes(), stats=_get_stats(),
        findings=_get_recent_findings(20), gas=_get_gas(),
        chain_names=CHAIN_NAMES, config_raw=_read_config(),
    ))


@app.get("/api/stats")
async def api_stats(): return JSONResponse(_get_stats())

@app.get("/api/processes")
async def api_processes():
    return JSONResponse([{"name": p["name"], "alive": p["alive"], "count": p["count"],
                          "desc": p["desc_short"], "instances": [
                              {"pid": i["pid"], "chain": i["chain"]} for i in p["instances"]
                          ]} for p in _get_processes()])

@app.get("/api/findings")
async def api_findings(n: int = 20, q: str = ""):
    findings = _get_recent_findings(n)
    if q:
        ql = q.lower()
        findings = [f for f in findings if ql in f["text"].lower() or ql in f["source"].lower()]
    return JSONResponse(findings)

@app.get("/api/gas")
async def api_gas(): return JSONResponse(_get_gas())

@app.get("/api/config")
async def api_get_config():
    return JSONResponse({"raw": _read_config()})

@app.post("/api/config/save")
async def api_save_config(raw: str = Form("")):
    try:
        with open(CONFIG_PATH, "w") as f: f.write(raw)
        return JSONResponse({"ok": True, "message": "Конфиг сохранён"})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=400)

@app.post("/api/process/restart")
async def api_restart_process(script: str = Form("")):
    if not script:
        return JSONResponse({"ok": False, "message": "Не указан скрипт"}, status_code=400)
    subprocess.run(["pkill", "-f", script], capture_output=True, text=True)
    time.sleep(1)
    log_file = os.path.join(BASE_DIR, "logs", script.replace(".py", ".log"))
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    try:
        subprocess.Popen(["python", script], cwd=BASE_DIR,
                         stdout=open(log_file, "a"), stderr=subprocess.STDOUT, start_new_session=True)
        return JSONResponse({"ok": True, "message": f"{script} перезапущен"})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)

@app.get("/api/logs/{script}")
async def api_logs(script: str, lines: int = 50):
    return JSONResponse({"script": script, "log": _get_log_tail(script, lines)})

@app.get("/api/pnl")
async def api_pnl():
    try:
        from src.pnl_tracker import get_snapshot
        snap = get_snapshot()
        start = snap.get("start_usd", 0)
        current = snap.get("current_usd", 0)
        return JSONResponse({
            "start_usd": start, "current_usd": current,
            "delta_usd": round(current - start, 2),
            "is_profitable": current >= start - 0.01,
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


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    WS_CLIENTS.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive
    except WebSocketDisconnect:
        pass
    finally:
        if ws in WS_CLIENTS:
            WS_CLIENTS.remove(ws)


async def _ws_broadcast(data: dict):
    dead = []
    for ws in WS_CLIENTS:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in WS_CLIENTS:
            WS_CLIENTS.remove(ws)


def _ws_pusher_loop():
    """Фоновый поток: собирает данные и пушит через WebSocket."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async def push():
        while True:
            try:
                stats = await asyncio.to_thread(_get_stats)
                procs = await asyncio.to_thread(_get_processes)
                findings = await asyncio.to_thread(_get_recent_findings, 15)
                gas = await asyncio.to_thread(_get_gas)
                from src.pnl_tracker import get_snapshot
                pnl = get_snapshot()
                await _ws_broadcast({
                    "type": "live",
                    "stats": stats, "processes": [
                        {"name": p["name"], "alive": p["alive"], "count": p["count"],
                         "desc": p["desc_short"], "instances": [
                             {"pid": i["pid"], "chain": i["chain"]} for i in p["instances"]
                         ]} for p in procs],
                    "findings": [{"source": f["source"], "text": f["text"]} for f in findings],
                    "gas": gas, "pnl": pnl,
                })
            except Exception:
                pass
            await asyncio.sleep(2)
    loop.run_until_complete(push())


@app.on_event("startup")
async def startup():
    try:
        from src.pnl_tracker import start_background
        start_background()
    except: pass
    threading.Thread(target=_ws_pusher_loop, daemon=True).start()
