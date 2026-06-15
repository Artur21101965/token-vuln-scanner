from src.scanners.checks.solana.authorities import MintAuthorityCheck, FreezeAuthorityCheck
from src.scanners.checks.solana.pool_ownership import PoolOwnershipCheck
from src.scanners.checks.solana.lp_locked import LpLockedSolanaCheck
from src.scanners.checks.solana.token_extensions import TokenExtensionsCheck

ALL_SOLANA_CHECKS = [
    MintAuthorityCheck,
    FreezeAuthorityCheck,
    PoolOwnershipCheck,
    LpLockedSolanaCheck,
    TokenExtensionsCheck,
]
