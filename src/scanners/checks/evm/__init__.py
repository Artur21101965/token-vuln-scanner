from src.scanners.checks.evm.mint import MintCheck
from src.scanners.checks.evm.honeypot import HoneypotCheck
from src.scanners.checks.evm.proxy import ProxyCheck
from src.scanners.checks.evm.hidden import HiddenSelfdestructCheck
from src.scanners.checks.evm.reentrancy import ReentrancyCheck
from src.scanners.checks.evm.burn import PublicBurnCheck
from src.scanners.checks.evm.permit import PermitCheck
from src.scanners.checks.evm.withdraw import WithdrawCheck
from src.scanners.checks.evm.approve_all import ApproveAllCheck
from src.scanners.checks.evm.ownership_transfer import OwnershipTransferCheck
from src.scanners.checks.evm.tax_update import TaxUpdateCheck
from src.scanners.checks.evm.initialize import InitializeCheck
from src.scanners.checks.evm.upgrade import UpgradeCheck
from src.scanners.checks.evm.scam_deployer import ScamDeployerCheck
from src.scanners.checks.evm.multi_send import MultiSendCheck
from src.scanners.checks.evm.verification import UnverifiedContractCheck
from src.scanners.checks.evm.supply_concentration import SupplyConcentrationCheck
from src.scanners.checks.evm.liquidity_burn import LiquidityBurnedCheck
from src.scanners.checks.evm.deployer_risk import CrossChainDeployerCheck
from src.scanners.checks.evm.supply_change import SupplyChangeCheck
from src.scanners.checks.evm.bytecode_selfdestruct import BytecodeSelfdestructCheck
from src.scanners.checks.evm.bytecode_delegatecall import BytecodeDelegatecallCheck
from src.scanners.checks.evm.bytecode_sstore import BytecodeSstoreCheck
from src.scanners.checks.evm.cross_contract import CrossContractCheck
from src.scanners.checks.evm.historical import HistoricalAnalysisCheck
from src.scanners.checks.evm.storage_layout import StorageLayoutCheck
from src.scanners.checks.evm.sandwich_flash import SandwichFlashCheck

ALL_EVM_CHECKS = [
    MintCheck,
    HoneypotCheck,
    ProxyCheck,
    HiddenSelfdestructCheck,
    ReentrancyCheck,
    PublicBurnCheck,
    PermitCheck,
    WithdrawCheck,
    ApproveAllCheck,
    OwnershipTransferCheck,
    TaxUpdateCheck,
    InitializeCheck,
    UpgradeCheck,
    ScamDeployerCheck,
    MultiSendCheck,
    UnverifiedContractCheck,
    SupplyConcentrationCheck,
    LiquidityBurnedCheck,
    CrossChainDeployerCheck,
    SupplyChangeCheck,
    BytecodeSelfdestructCheck,
    BytecodeDelegatecallCheck,
    BytecodeSstoreCheck,
    CrossContractCheck,
    HistoricalAnalysisCheck,
    StorageLayoutCheck,
    SandwichFlashCheck,
]
