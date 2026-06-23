# False Positive Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate false positives from fallback contracts and misidentified function selectors in EVM bytecode

**Architecture:** Add fallback detection + dispatch table parser to verify selectors are genuinely callable. Add confidence scoring to replace binary CONFIRMED/DISMISSED. Filter low-confidence findings from reports.

**Tech Stack:** Python 3.12, EVM bytecode parsing (existing disassembler), pytest

---

### Task 1: DataCollector.fallback_detected()

**Files:**
- Modify: `src/data.py:DataCollector` +method
- Test: `tests/test_data.py` +tests

- [ ] **Step 1: Write the failing test**

```python
# tests/test_data.py
from unittest.mock import Mock
from src.data import DataCollector
from src.rpc import RpcClient

def test_fallback_detected_true():
    rpc = Mock(spec=RpcClient)
    rpc.call.side_effect = lambda m, p: "0x" if m == "eth_call" else None
    dc = DataCollector(rpc, Mock())
    result = dc.fallback_detected("0xabc")
    assert result is True

def test_fallback_detected_false():
    rpc = Mock(spec=RpcClient)
    rpc.call.side_effect = lambda m, p: "0x" if m == "eth_getCode" else None
    # eth_call should raise (revert)
    rpc.call.side_effect = lambda m, p: (
        "0x" if m == "eth_getCode" else
        exec('raise RuntimeError("execution reverted")')
    )
    dc = DataCollector(rpc, Mock())
    result = dc.fallback_detected("0xabc")
    assert result is False

def test_fallback_detected_rpc_error():
    rpc = Mock(spec=RpcClient)
    rpc.call.side_effect = RuntimeError("connection failed")
    dc = DataCollector(rpc, Mock())
    result = dc.fallback_detected("0xabc")
    assert result is False  # graceful degradation
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_data.py::test_fallback_detected_true -x -v`
Expected: FAIL with "AttributeError: 'DataCollector' object has no attribute 'fallback_detected'"

- [ ] **Step 3: Implement fallback_detected(addr) method**

Add method to `DataCollector`:

```python
def fallback_detected(self, address: str) -> bool:
    try:
        data = "0xdeadbeef" + "0" * 64
        self._rpc.call("eth_call", [{"to": address, "data": data}, "latest"])
        return True
    except Exception:
        return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_data.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/data.py tests/test_data.py
git commit -m "feat: add fallback detection to DataCollector"
```

---

### Task 2: Dispatch Table Parser

**Files:**
- Create: `src/evm/dispatch_table.py`
- Test: `tests/test_evm/test_dispatch_table.py`

- [ ] **Step 1: Write failing tests**

```tests/test_evm/test_dispatch_table.py
from src.evm.dispatch_table import parse_dispatch_table

def test_parse_simple_router():
    # Uniswap V2 Router 0x7a250d5630b4cf539739df2c5dacb4c659f2488d
    # Simplified dispatcher: CALLDATALOAD(0x00) PUSH1 0xe0 SHR DUP1 PUSH4 0x38ed1739 EQ PUSH2 dest JUMPI ...
    # Build minimal bytecode with actual dispatcher
    bytecode = "0x" + "".join([
        "6000",          # PUSH1 0x00
        "35",            # CALLDATALOAD
        "600e",          # PUSH1 0xe0 (actually wrong but test pattern)
        "1c",            # SHR
        "80",            # DUP1
        "6338ed1739",   # PUSH4 0x38ed1739
        "14",            # EQ
        "61" + "0100".zfill(4),  # PUSH2 0x0100
        "57",            # JUMPI
        "fd",            # REVERT
    ])
    selectors, fallback = parse_dispatch_table(bytecode)
    assert "38ed1739" in selectors
    assert selectors["38ed1739"] == 0x0100
    assert fallback is None

def test_parse_with_fallback():
    # Dispatcher with fallback at end (no REVERT after dispatch)
    bytecode = "0x" + "".join([
        "6000", "35", "600e", "1c", "80",
        "6302e1a7d4d", "14", "61" + "0200".zfill(4), "57",
        "6000", "80", "fd",  # fallback: RETURN(0, 0)
    ])
    selectors, fallback = parse_dispatch_table(bytecode)
    assert "02e1a7d4d" in selectors
    assert fallback is not None

def test_parse_no_dispatcher():
    bytecode = "0x60006000fd"
    selectors, fallback = parse_dispatch_table(bytecode)
    assert selectors == {}
    assert fallback is False

def test_parse_real_forwarding():
    # Contract with catch-all forwarding (no dispatcher, just code)
    bytecode = "0x60006000fd"
    selectors, fallback = parse_dispatch_table(bytecode)
    assert selectors == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_evm/test_dispatch_table.py -x -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement dispatch table parser**

```python
# src/evm/dispatch_table.py
from typing import Optional
from src.evm.disassembler import disassemble

def parse_dispatch_table(bytecode: str) -> tuple[dict[str, int], Optional[bool]]:
    instrs = disassemble(bytecode)
    selectors: dict[str, int] = {}
    has_fallback = False

    for i, inst in enumerate(instrs):
        if _is_dispatch_entry(instrs, i):
            sel_hex = inst.push_data.hex()
            dest_offset = _get_jump_dest(instrs, i + 4)
            if dest_offset is not None:
                selectors[sel_hex] = dest_offset
            i += 5
            continue

    # Check for fallback (no REVERT after last dispatch entry)
    last_entry_idx = -1
    for i, inst in enumerate(instrs):
        if inst.name == "REVERT" and i > last_entry_idx:
            break
    else:
        has_fallback = True

    return selectors, has_fallback if selectors else None


def _is_dispatch_entry(instrs: list, idx: int) -> bool:
    if idx + 4 >= len(instrs):
        return False
    inst = instrs[idx]
    if not inst.name.startswith("PUSH") or not inst.push_data:
        return False
    if len(inst.push_data) not in (2, 3, 4):
        return False
    if instrs[idx + 1].name != "EQ":
        return False
    if instrs[idx + 2].name != "PUSH2":
        return False
    if instrs[idx + 4].name != "JUMPI":
        return False
    return True


def _get_jump_dest(instrs: list, push_instr_idx: int) -> Optional[int]:
    inst = instrs[push_instr_idx]
    if inst.name == "PUSH2" and inst.push_data:
        return int.from_bytes(inst.push_data, "big")
    return None


def is_selector_in_dispatch(bytecode: str, selector_hex: str) -> bool:
    selectors, _ = parse_dispatch_table(bytecode)
    return selector_hex in selectors


def get_callable_selectors(bytecode: str) -> set[str]:
    selectors, _ = parse_dispatch_table(bytecode)
    return set(selectors.keys())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_evm/test_dispatch_table.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/evm/dump_test.py src/evm/dispatch_table.py tests/test_evm/test_dispatch_table.py
git commit -m "feat: dispatch table parser for EVM bytecode"
```

---

### Task 3: Add dispatch_selectors and fallback to CheckContext

**Files:**
- Modify: `src/scanners/base.py`

- [ ] **Step 1: Add fields + build logic in BaseScanner.scan()**

Add to `CheckContext`:
```python
@dataclass
class CheckContext:
    token: TokenInfo
    pool: PoolInfo
    data_collector: DataCollector
    rpc: RpcClient
    deployer_store: Optional[DeployerStore] = None
    dispatch_selectors: set[str] = field(default_factory=set)
    has_fallback: bool = False
```

In `BaseScanner.scan()` (src/scanners/base.py:57-78), after `ctx = CheckContext(...)` and before the check loop, add:
```python
from src.evm.dispatch_table import parse_dispatch_table

bytecode = self._data.get_code(token.address) or ""
if bytecode:
    selectors, _ = parse_dispatch_table(bytecode)
    ctx.dispatch_selectors = set(selectors.keys())
    ctx.has_fallback = self._data.fallback_detected(token.address)
```

- [ ] **Step 3: Commit**

```bash
git add src/scanners/base.py
git commit -m "feat: add dispatch_selectors and has_fallback to CheckContext"
```

---

### Task 4: Confidence Scorer

**Files:**
- Create: `src/verifiers/confidence.py`
- Test: `tests/test_verifiers/test_confidence.py`

- [ ] **Step 1: Write confidence score tests**

```python
# tests/test_verifiers/test_confidence.py
from src.verifiers.confidence import score_confidence, filter_by_confidence
from src.types import Finding, Severity

def test_score_fallback_only():
    score = score_confidence(has_fallback=True, in_dispatch_table=False, eth_call_succeeded=True)
    assert score < 0.3

def test_score_fallback_with_dispatch():
    score = score_confidence(has_fallback=True, in_dispatch_table=True, eth_call_succeeded=True)
    assert 0.2 < score < 0.5

def test_score_no_fallback_with_dispatch():
    score = score_confidence(has_fallback=False, in_dispatch_table=True, eth_call_succeeded=True)
    assert score >= 0.7

def test_score_eth_call_reverted():
    score = score_confidence(has_fallback=False, in_dispatch_table=True, eth_call_succeeded=False)
    assert score < 0.1

def test_score_only_owner_check_passed():
    score = score_confidence(has_fallback=False, in_dispatch_table=True, eth_call_succeeded=True, only_owner_bypassed=True)
    assert score >= 0.9

def test_filter_removes_low_confidence():
    f = Finding(check_name="test", severity=Severity.CRITICAL, description="", recommendation="")
    result = filter_by_confidence([f], {id(f): 0.2})
    assert len(result) == 0

def test_filter_keeps_high_confidence():
    f = Finding(check_name="test", severity=Severity.CRITICAL, description="", recommendation="")
    result = filter_by_confidence([f], {id(f): 0.8})
    assert len(result) == 1
```

- [ ] **Step 2: Implement confidence scorer**

```python
# src/verifiers/confidence.py
from src.types import Finding

CONFIDENCE_THRESHOLD = 0.5

def score_confidence(
    has_fallback: bool = False,
    in_dispatch_table: bool = False,
    eth_call_succeeded: bool = False,
    only_owner_bypassed: bool = False,
    selector_based: bool = False,
) -> float:
    if not selector_based:
        return 1.0  # checks not based on selectors (supply, holder, etc.)
    if has_fallback and not in_dispatch_table:
        return 0.0
    if has_fallback and in_dispatch_table and eth_call_succeeded:
        return 0.3
    if not has_fallback and not in_dispatch_table:
        return 0.1
    if not has_fallback and in_dispatch_table and not eth_call_succeeded:
        return 0.0
    if not has_fallback and in_dispatch_table and eth_call_succeeded:
        if only_owner_bypassed:
            return 0.9
        return 0.7
    return 0.5


def filter_by_confidence(findings: list[Finding], scores: dict[int, float]) -> list[Finding]:
    return [f for f in findings if scores.get(id(f), 1.0) >= CONFIDENCE_THRESHOLD]


def demote_fallback_findings(findings: list[Finding], scores: dict[int, float]) -> list[Finding]:
    result = []
    for f in findings:
        score = scores.get(id(f), 1.0)
        if score < 0.3 and f.severity.value < 3:
            f.severity = Severity(max(f.severity.value + 1, 3))  # demote by one
        result.append(f)
    return result
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_verifiers/test_confidence.py -x -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/verifiers/confidence.py tests/test_verifiers/test_confidence.py
git commit -m "feat: add confidence scoring system"
```

---

### Task 5: Integrate confidence scoring into scanner pipeline

**Files:**
- Modify: `src/scanners/base.py`
- Test: `tests/test_evm_scanner.py` +cases

- [ ] **Step 1: Add confidence pass to scan report flow**

In `EvmScanner.scan()` (or equivalent base), after running all checks and before returning:

```python
from src.verifiers.confidence import score_confidence, filter_by_confidence, demote_fallback_findings

scores = {}
for f in findings:
    has_fb = ctx.has_fallback
    in_dt = any(f.check_name == c for c in ctx.dispatch_selectors)  # simplified
    eth_ok = getattr(f, "_eth_call_succeeded", True)
    score = score_confidence(
        has_fallback=has_fb,
        in_dispatch_table=in_dt,
        eth_call_succeeded=eth_ok,
        selector_based=hasattr(f, "_selector_based"),
    )
    scores[id(f)] = score
    f.confidence = score

findings = demote_fallback_findings(findings, scores)
findings = filter_by_confidence(findings, scores)
report.findings = findings
```

If Finding is a dataclass, add a `confidence: float = 1.0` field.

- [ ] **Step 2: Update Finding type with confidence field**

```python
# src/types.py
@dataclass
class Finding:
    # ... existing fields ...
    confidence: float = 1.0
```

- [ ] **Step 3: Write integration test**

```python
# tests/test_evm_scanner.py (add test)
def test_confidence_filters_fallback_false_positive():
    # Forwarding contract with fallback - withdraw finding should be demoted/filtered
    scanner = create_test_scanner()
    ctx = create_test_context()
    ctx.has_fallback = True
    ctx.dispatch_selectors = set()
    report = scanner.scan(ctx)
    for f in report.findings:
        if "withdraw" in f.check_name:
            assert f.confidence < 0.3
```

- [ ] **Step 4: Commit**

```bash
git add src/scanners/base.py src/types.py tests/test_evm_scanner.py
git commit -m "feat: integrate confidence scoring into scan pipeline"
```

---

### Task 6: Update selector-based checks to flag _selector_based

**Files:**
- Modify: all checks in `src/scanners/checks/evm/` that match by ABI/selector (mint, withdraw, upgrade, burn, ownership_transfer, tax_update, initialize, approve_all, reentrancy, permit, hidden, pause, limits, proxy, ownership)
- Test: existing tests (no new ones needed)

- [ ] **Step 1: Add _selector_based flag to selector-using checks**

Read each of these files and add `finding._selector_based = True` after creating any Finding that was triggered by a function selector or ABI signature match:

```
src/scanners/checks/evm/mint.py
src/scanners/checks/evm/withdraw.py
src/scanners/checks/evm/upgrade.py
src/scanners/checks/evm/burn.py
src/scanners/checks/evm/ownership_transfer.py
src/scanners/checks/evm/tax_update.py
src/scanners/checks/evm/initialize.py
src/scanners/checks/evm/approve_all.py
src/scanners/checks/evm/reentrancy.py
src/scanners/checks/evm/permit.py
src/scanners/checks/evm/hidden.py
src/scanners/checks/evm/proxy.py
src/scanners/checks/evm/ownership.py
```

In each file, find all lines like `Finding(` and `return Finding(` or `findings.append(Finding(`. After the closing `)` of each Finding constructor, add:
```python
finding._selector_based = True  # mark for confidence scoring
```

Note: `finding` is the variable name used in most files. Some files use `findings.append(Finding(...))` — in those cases, assign to a variable first, then append:
```python
finding = Finding(check_name=..., ...)
finding._selector_based = True
findings.append(finding)
```

- [ ] **Step 2: Run existing tests to confirm nothing broke**

Run: `uv run pytest -x -q`
Expected: All passing

- [ ] **Step 3: Commit**

```bash
git commit -am "feat: mark selector-based findings for confidence scoring"
```

---

### Task 7: Verify fix against known false positive

**Files:**
- Test: `tests/test_checks/test_withdraw.py` (create)

- [ ] **Step 1: Write integration test with the forwarding contract**

- [ ] **Step 2: Run end-to-end test**

Run: `uv run pytest -x -q`
Expected: All passing, no false positives

- [ ] **Step 3: Commit**

```bash
git commit -am "test: verify forwarding contract no longer produces false CRITICAL"
```

---

### Task 8: Integration test — real 0x51c7 address

**Files:**
- Test: `tests/test_integration/test_false_positive_regression.py`

- [ ] **Step 1: Write regression test mocking RPC**

```python
def test_forwarding_contract_regression():
    # Simulate scanning 0x51C72848c68a965f66FA7a88855F9f7784502a7F
    rpc = Mock(spec=RpcClient)
    rpc.call.side_effect = forwarding_rpc_mock()
    dc = DataCollector(rpc, Mock())
    fallback = dc.fallback_detected("0x51c7...")
    assert fallback is True  # forwarding contract has fallback

    bytecode = forwarding_bytecode()
    selectors, fb = parse_dispatch_table(bytecode)
    assert "2e1a7d4d" not in selectors  # withdraw NOT in dispatch table

    score = score_confidence(has_fallback=True, in_dispatch_table=False, eth_call_succeeded=True)
    assert score < 0.3  # filtered out
```

- [ ] **Step 2: Run test**

Run: `uv run pytest tests/test_integration/ -x -q`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git commit -am "test: regression test for forwarding contract"
```

---

### Task 9: Run full test suite

- [ ] **Step 1: Run all tests**

Run: `uv run pytest -x -q`
Expected: All pass

- [ ] **Step 2: Update test count if needed**

Check scanner count assertions: `tests/test_evm_scanner.py` line with `assert len(scanner.checks) ==`

- [ ] **Step 3: Final commit**

```bash
git commit -am "chore: update test assertions"
```
