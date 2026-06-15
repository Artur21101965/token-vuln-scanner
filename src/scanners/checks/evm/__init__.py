from src.scanners.checks.evm.ownership import OwnerNotRenouncedCheck
from src.scanners.checks.evm.mint import MintCheck
from src.scanners.checks.evm.lp_safety import LpNotBurnedCheck
from src.scanners.checks.evm.honeypot import HoneypotCheck
from src.scanners.checks.evm.proxy import ProxyCheck
from src.scanners.checks.evm.pausable import PausableCheck
from src.scanners.checks.evm.tax import HighTaxCheck
from src.scanners.checks.evm.blacklist import BlacklistCheck
from src.scanners.checks.evm.limits import MaxTxLimitCheck, MaxWalletLimitCheck
from src.scanners.checks.evm.hidden import HiddenSelfdestructCheck
from src.scanners.checks.evm.reentrancy import ReentrancyCheck
from src.scanners.checks.evm.access_control import AccessControlCheck

ALL_EVM_CHECKS = [
    OwnerNotRenouncedCheck,
    MintCheck,
    LpNotBurnedCheck,
    HoneypotCheck,
    ProxyCheck,
    PausableCheck,
    HighTaxCheck,
    BlacklistCheck,
    MaxTxLimitCheck,
    MaxWalletLimitCheck,
    HiddenSelfdestructCheck,
    ReentrancyCheck,
    AccessControlCheck,
]
