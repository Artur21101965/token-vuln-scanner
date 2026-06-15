from src.scanners.checks.evm.ownership import OwnerNotRenouncedCheck
from src.scanners.checks.evm.mint import MintCheck
from src.scanners.checks.evm.lp_safety import LpNotBurnedCheck
from src.scanners.checks.evm.honeypot import HoneypotCheck

ALL_EVM_CHECKS = [
    OwnerNotRenouncedCheck,
    MintCheck,
    LpNotBurnedCheck,
    HoneypotCheck,
]
