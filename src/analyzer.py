import logging
import time
from src.db.queue import TokenQueue
from src.scanners.evm_scanner import EvmScanner
from src.scanners.solana_scanner import SolanaScanner
from src.reporter.json_report import JsonReporter
from src.types import Chain, TokenInfo, PoolInfo

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(
        self,
        queue: TokenQueue,
        evm_scanner: EvmScanner,
        solana_scanner: SolanaScanner,
        reporter: JsonReporter,
    ):
        self._queue = queue
        self._evm_scanner = evm_scanner
        self._solana_scanner = solana_scanner
        self._reporter = reporter

    def process_one(self) -> bool:
        token = self._queue.claim_next()
        if token is None:
            return False

        logger.info("Analyzing %s on %s", token.symbol, token.chain)
        try:
            chain = Chain.from_str(token.chain)
            token_info = TokenInfo(
                address=token.token_address,
                symbol=token.symbol,
                chain=chain,
            )
            pool_info = PoolInfo(
                address=token.pair_address,
                dex=token.dex,
                liquidity_usd=token.liquidity_usd,
            )

            if chain in (Chain.ETHEREUM, Chain.BSC):
                report = self._evm_scanner.scan(token_info, pool_info)
            elif chain == Chain.SOLANA:
                report = self._solana_scanner.scan(token_info, pool_info)
            else:
                self._queue.mark_failed(token.row_id, error=f"Unknown chain: {token.chain}")
                return True

            self._reporter.write(report)
            self._queue.mark_done(token.row_id)
            logger.info("Done %s — %s", token.symbol, report.summary)
            return True

        except Exception as exc:
            logger.error("Failed to analyze %s: %s", token.symbol, exc)
            self._queue.mark_failed(token.row_id, error=str(exc))
            return True

    def run(self, interval: float = 1.0):
        logger.info("Analyzer started")
        while True:
            try:
                if not self.process_one():
                    time.sleep(interval)
            except KeyboardInterrupt:
                break
            except Exception as exc:
                logger.error("Analyzer error: %s", exc)
                time.sleep(5)
