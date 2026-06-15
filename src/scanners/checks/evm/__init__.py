from src.scanners.checks.evm.ownership import OwnerNotRenouncedCheck
from src.scanners.checks.evm.mint import MintCheck

ALL_EVM_CHECKS = [
    OwnerNotRenouncedCheck,
    MintCheck,
]
