from src.scanners.checks.solana.authorities import MintAuthorityCheck, FreezeAuthorityCheck
from src.scanners.checks.solana.pool_ownership import PoolOwnershipCheck

ALL_SOLANA_CHECKS = [
    MintAuthorityCheck,
    FreezeAuthorityCheck,
    PoolOwnershipCheck,
]
