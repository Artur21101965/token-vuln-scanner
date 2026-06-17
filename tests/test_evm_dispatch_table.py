import pytest
from src.evm.dispatch_table import parse_dispatch_table, is_selector_in_dispatch, get_callable_selectors


class TestParseDispatchTable:
    def test_parse_simple_router(self):
        bytecode = "0x" + "".join([
            "6000",          # PUSH1 0x00
            "35",            # CALLDATALOAD
            "600e",          # PUSH1 0x0e (14)
            "1c",            # SHR
            "80",            # DUP1
            "6338ed1739",   # PUSH4 0x38ed1739
            "14",            # EQ
            "610100",        # PUSH2 0x0100
            "57",            # JUMPI
            "fd",            # REVERT
        ])
        selectors, fallback = parse_dispatch_table(bytecode)
        assert "38ed1739" in selectors
        assert selectors["38ed1739"] == 0x0100
        assert fallback is False

    def test_parse_with_fallback(self):
        bytecode = "0x" + "".join([
            "6000", "35", "600e", "1c", "80",
            "6302e1a7d4", "14", "610200", "57",
            "fd",                    # REVERT
            "6000", "6000", "f3",   # fallback: RETURN(0, 0)
        ])
        selectors, fallback = parse_dispatch_table(bytecode)
        assert "02e1a7d4" in selectors
        assert fallback is True

    def test_parse_multi_selector(self):
        bytecode = "0x" + "".join([
            "6000", "35", "600e", "1c", "80",
            "63aabbccdd", "14", "610100", "57",
            "80",
            "63deadbeef", "14", "610200", "57",
            "fd",
        ])
        selectors, fallback = parse_dispatch_table(bytecode)
        assert "aabbccdd" in selectors
        assert selectors["aabbccdd"] == 0x0100
        assert "deadbeef" in selectors
        assert selectors["deadbeef"] == 0x0200
        assert len(selectors) == 2
        assert fallback is False

    def test_parse_no_dispatcher(self):
        bytecode = "0x60006000fd"
        selectors, fallback = parse_dispatch_table(bytecode)
        assert selectors == {}
        assert fallback is None

    def test_parse_empty(self):
        selectors, fallback = parse_dispatch_table("0x")
        assert selectors == {}
        assert fallback is None


class TestIsSelectorInDispatch:
    def test_selector_found(self):
        bytecode = "0x" + "".join([
            "6000", "35", "600e", "1c", "80",
            "6338ed1739", "14", "610100", "57",
            "fd",
        ])
        assert is_selector_in_dispatch(bytecode, "38ed1739") is True

    def test_selector_not_found(self):
        bytecode = "0x" + "".join([
            "6000", "35", "600e", "1c", "80",
            "6338ed1739", "14", "610100", "57",
            "fd",
        ])
        assert is_selector_in_dispatch(bytecode, "deadbeef") is False


class TestGetCallableSelectors:
    def test_returns_selectors(self):
        bytecode = "0x" + "".join([
            "6000", "35", "600e", "1c", "80",
            "6338ed1739", "14", "610100", "57",
            "fd",
        ])
        sels = get_callable_selectors(bytecode)
        assert sels == {"38ed1739"}
