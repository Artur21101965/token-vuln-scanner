from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional
from src.types import DeployerInfo

SCAMMER_CRITICAL_THRESHOLD = 3


class DeployerStore:
    def __init__(self, db_path: str = "scanner.db"):
        self.db_path = db_path

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS deployers ("
                "  address TEXT PRIMARY KEY,"
                "  chain_name TEXT NOT NULL DEFAULT '',"
                "  token_count INTEGER NOT NULL DEFAULT 0,"
                "  critical_count INTEGER NOT NULL DEFAULT 0,"
                "  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS deployer_tokens ("
                "  row_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  deployer_address TEXT NOT NULL,"
                "  token_address TEXT NOT NULL,"
                "  chain_name TEXT NOT NULL,"
                "  has_critical INTEGER NOT NULL DEFAULT 0,"
                "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "  UNIQUE(deployer_address, token_address)"
                ")"
            )
            conn.commit()

    def get(self, address: str) -> Optional[DeployerInfo]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT address, chain_name, token_count, critical_count, "
                "COALESCE(first_seen, '') FROM deployers WHERE address = ?",
                (address,),
            ).fetchone()
            if row is None:
                return None
            return DeployerInfo(
                address=row[0],
                chain_name=row[1],
                token_count=row[2],
                critical_count=row[3],
                first_seen=row[4],
            )

    def upsert(self, info: DeployerInfo):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO deployers (address, chain_name, token_count, critical_count) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(address) DO UPDATE SET "
                "chain_name = excluded.chain_name, "
                "token_count = excluded.token_count, "
                "critical_count = excluded.critical_count",
                (info.address, info.chain_name, info.token_count, info.critical_count),
            )
            conn.commit()

    def add_token(self, deployer_address: str, chain_name: str, has_critical: bool):
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO deployer_tokens "
                "(deployer_address, token_address, chain_name, has_critical) "
                "VALUES (?, ?, ?, ?)",
                (deployer_address, f"__count_{chain_name}", chain_name, 1 if has_critical else 0),
            )
            conn.execute(
                "INSERT INTO deployers (address, chain_name, token_count, critical_count) "
                "VALUES (?, ?, 1, ?) "
                "ON CONFLICT(address) DO UPDATE SET "
                "token_count = token_count + 1, "
                "critical_count = critical_count + ?",
                (deployer_address, chain_name, 1 if has_critical else 0, 1 if has_critical else 0),
            )
            conn.commit()

    def is_known_scammer(self, address: str) -> bool:
        info = self.get(address)
        if info is None:
            return False
        return info.critical_count >= SCAMMER_CRITICAL_THRESHOLD

    def get_stats(self, address: str) -> dict:
        info = self.get(address)
        if info is None:
            return {"token_count": 0, "critical_count": 0}
        return {"token_count": info.token_count, "critical_count": info.critical_count}
