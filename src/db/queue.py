from __future__ import annotations

import sqlite3
from decimal import Decimal
from typing import Optional

from src.types import Chain, TokenStatus, PendingToken


class TokenQueue:
    def __init__(self, db_path: str = "scanner.db") -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS pending_tokens ("
                "  row_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  chain TEXT NOT NULL,"
                "  token_address TEXT NOT NULL,"
                "  pair_address TEXT NOT NULL,"
                "  symbol TEXT NOT NULL,"
                "  liquidity_usd TEXT NOT NULL,"
                "  dex TEXT NOT NULL,"
                "  status TEXT NOT NULL DEFAULT 'pending',"
                "  error TEXT NOT NULL DEFAULT '',"
                "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "  UNIQUE(token_address, pair_address)"
                ")"
            )
            conn.commit()

    def add(
        self,
        chain: Chain,
        token_address: str,
        pair_address: str,
        symbol: str,
        liquidity_usd: Decimal,
        dex: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO pending_tokens "
                "(chain, token_address, pair_address, symbol, liquidity_usd, dex, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    chain.name.lower(),
                    token_address,
                    pair_address,
                    symbol,
                    str(liquidity_usd),
                    dex,
                    TokenStatus.PENDING.value,
                ),
            )
            conn.commit()

    def count_pending(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM pending_tokens WHERE status = ?",
                (TokenStatus.PENDING.value,),
            ).fetchone()
            return row[0] if row else 0

    def _row_to_pending(self, row: tuple) -> PendingToken:
        return PendingToken(
            row_id=row[0],
            chain=Chain.from_str(row[1]),
            token_address=row[2],
            pair_address=row[3],
            symbol=row[4],
            liquidity_usd=Decimal(row[5]),
            dex=row[6],
            status=TokenStatus(row[7]),
            error=row[8],
        )

    def claim_next_batch(self, n: int) -> list[PendingToken]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT row_id, chain, token_address, pair_address, symbol, "
                "liquidity_usd, dex, status, error "
                "FROM pending_tokens WHERE status = ? ORDER BY created_at ASC LIMIT ?",
                (TokenStatus.PENDING.value, n),
            ).fetchall()
            if not rows:
                return []
            ids = [r[0] for r in rows]
            placeholders = ",".join("?" for _ in ids)
            conn.execute(
                f"UPDATE pending_tokens SET status = ? WHERE row_id IN ({placeholders})",
                (TokenStatus.ANALYZING.value, *ids),
            )
            conn.commit()
            return [
                PendingToken(
                    row_id=r[0],
                    chain=Chain.from_str(r[1]),
                    token_address=r[2],
                    pair_address=r[3],
                    symbol=r[4],
                    liquidity_usd=Decimal(r[5]),
                    dex=r[6],
                    status=TokenStatus.ANALYZING,
                    error=r[8],
                )
                for r in rows
            ]

    def claim_next(self) -> Optional[PendingToken]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT row_id, chain, token_address, pair_address, symbol, "
                "liquidity_usd, dex, status, error "
                "FROM pending_tokens WHERE status = ? ORDER BY created_at ASC LIMIT 1",
                (TokenStatus.PENDING.value,),
            ).fetchone()
            if row is None:
                return None
            token = self._row_to_pending(row)
            conn.execute(
                "UPDATE pending_tokens SET status = ? WHERE row_id = ?",
                (TokenStatus.ANALYZING.value, token.row_id),
            )
            conn.commit()
            return PendingToken(
                row_id=token.row_id,
                chain=token.chain,
                token_address=token.token_address,
                pair_address=token.pair_address,
                symbol=token.symbol,
                liquidity_usd=token.liquidity_usd,
                dex=token.dex,
                status=TokenStatus.ANALYZING,
                error=token.error,
            )

    def mark_done(self, token_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pending_tokens SET status = ? WHERE row_id = ?",
                (TokenStatus.DONE.value, token_id),
            )
            conn.commit()

    def mark_failed(self, token_id: int, error: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pending_tokens SET status = ?, error = ? WHERE row_id = ?",
                (TokenStatus.FAILED.value, error, token_id),
            )
            conn.commit()

    def get(self, token_id: int) -> Optional[PendingToken]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT row_id, chain, token_address, pair_address, symbol, "
                "liquidity_usd, dex, status, error "
                "FROM pending_tokens WHERE row_id = ?",
                (token_id,),
            ).fetchone()
            return self._row_to_pending(row) if row else None
