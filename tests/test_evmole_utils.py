import pytest
from src.evmole_utils import (
    get_functions, find_dangerous_functions,
    has_dangerous_function, get_selectors
)

EVMOLE_README_CODE = (
    "0x6080604052348015600e575f80fd5b50600436106030575f3560e01c8063"
    "2125b65b146034578063b69ef8a8146044575b5f80fd5b6044603f36600460"
    "46565b505050565b005b5f805f606084860312156057575f80fd5b833563ff"
    "ffffff811681146069575f80fd5b925060208401356001600160a01b038116"
    "81146083575f80fd5b915060408401356001600160e01b0381168114609d57"
    "5f80fd5b80915050925092509256"
)

TINY_CODE = "0x6080604052"


class TestGetFunctions:
    def test_returns_functions_from_bytecode(self):
        fns = get_functions(EVMOLE_README_CODE)
        assert len(fns) >= 2

    def test_returns_empty_list_for_empty_code(self):
        assert get_functions("") == []
        assert get_functions("0x") == []
        assert get_functions("0x1234") == []

    def test_each_function_has_selector(self):
        fns = get_functions(EVMOLE_README_CODE)
        for fn in fns:
            assert len(fn.selector) == 8
            assert isinstance(fn.selector, str)

    def test_each_function_has_arguments(self):
        fns = get_functions(EVMOLE_README_CODE)
        for fn in fns:
            assert isinstance(fn.arguments, str)

    def test_each_function_has_mutability(self):
        fns = get_functions(EVMOLE_README_CODE)
        for fn in fns:
            assert fn.state_mutability in ("nonpayable", "payable", "view", "pure")

    def test_tiny_bytecode_returns_empty(self):
        assert get_functions(TINY_CODE) == []


class TestGetSelectors:
    def test_returns_set_of_selectors(self):
        sels = get_selectors(EVMOLE_README_CODE)
        assert isinstance(sels, set)
        assert "2125b65b" in sels
        assert "b69ef8a8" in sels

    def test_empty_for_no_code(self):
        assert get_selectors("") == set()
        assert get_selectors("0x") == set()


class TestHasDangerousFunction:
    def test_detects_known_selector(self):
        assert has_dangerous_function(EVMOLE_README_CODE, "2125b65b")

    def test_returns_false_for_unknown(self):
        assert not has_dangerous_function(EVMOLE_README_CODE, "deadbeef")

    def test_empty_code_returns_false(self):
        assert not has_dangerous_function("", "2125b65b")


class TestFindDangerousFunctions:
    def test_returns_list(self):
        dangerous = find_dangerous_functions(EVMOLE_README_CODE)
        assert isinstance(dangerous, list)

    def test_each_result_has_required_keys(self):
        dangerous = find_dangerous_functions(EVMOLE_README_CODE)
        for d in dangerous:
            assert "selector" in d
            assert "signature" in d
            assert "arguments" in d
            assert "state_mutability" in d
            assert "offset" in d

    def test_empty_code_returns_empty_list(self):
        assert find_dangerous_functions("") == []
        assert find_dangerous_functions("0x") == []
