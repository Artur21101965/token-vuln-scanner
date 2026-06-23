import pytest
from src.evm.disassembler import disassemble, opcode_name, push_imm_size, OPCODES


class TestDisassemble:
    def test_empty_bytecode(self):
        assert disassemble("") == []
        assert disassemble("0x") == []

    def test_single_stop(self):
        result = disassemble("0x00")
        assert len(result) == 1
        assert result[0].name == "STOP"
        assert result[0].offset == 0

    def test_push1_with_data(self):
        result = disassemble("0x6001")
        assert len(result) == 1
        assert result[0].name == "PUSH1"
        assert result[0].push_data.hex() == "01"
        assert result[0].offset == 0

    def test_push4_with_data(self):
        result = disassemble("0x63aabbccdd")
        assert len(result) == 1
        assert result[0].name == "PUSH4"
        assert len(result[0].push_data) == 4

    def test_multiple_instructions(self):
        # PUSH1 0x01, PUSH1 0x02, ADD, STOP
        bytecode = "0x600160020100"
        result = disassemble(bytecode)
        assert len(result) == 4
        names = [inst.name for inst in result]
        assert names == ["PUSH1", "PUSH1", "ADD", "STOP"]
        # Check offsets
        assert result[0].offset == 0  # PUSH1 at 0
        assert result[1].offset == 2  # PUSH1 at 2
        assert result[2].offset == 4  # ADD at 4
        assert result[3].offset == 5  # STOP at 5

    def test_selfdestruct_detected(self):
        # PUSH1 0, PUSH1 0, SELFDESTRUCT
        bytecode = "0x60006000ff"
        result = disassemble(bytecode)
        assert any(i.name == "SELFDESTRUCT" for i in result)

    def test_delegatecall_detected(self):
        # DELEGATECALL
        bytecode = "0x60006000600060006000f4"
        result = disassemble(bytecode)
        assert any(i.name == "DELEGATECALL" for i in result)

    def test_sstore_detected(self):
        # SSTORE
        bytecode = "0x6000600055"
        result = disassemble(bytecode)
        assert any(i.name == "SSTORE" for i in result)

    def test_push_range_sizes(self):
        for i in range(1, 33):
            op = 0x5f + i
            size = push_imm_size(op)
            assert size == i, f"PUSH{i}: expected size {i}, got {size}"

    def test_push_opcode_names(self):
        assert opcode_name(0x60) == "PUSH1"
        assert opcode_name(0x6f) == "PUSH16"
        assert opcode_name(0x7f) == "PUSH32"

    def test_multiple_push_variants(self):
        # PUSH1 0x01, PUSH2 0x0203
        bytecode = "0x6001610203"
        result = disassemble(bytecode)
        assert len(result) == 2
        assert result[0].name == "PUSH1"
        assert result[0].push_data.hex() == "01"
        assert result[1].name == "PUSH2"
        assert result[1].push_data.hex() == "0203"

    def test_opcode_name_known(self):
        assert opcode_name(0x00) == "STOP"
        assert opcode_name(0xFF) == "SELFDESTRUCT"
        assert opcode_name(0x60) == "PUSH1"

    def test_opcode_name_unknown(self):
        assert opcode_name(0xAA) == "UNKNOWN"


class TestOpcodeName:
    def test_dangerous_opcodes_defined(self):
        assert "SELFDESTRUCT" in OPCODES.values()
        assert "DELEGATECALL" in OPCODES.values()
        assert "SSTORE" in OPCODES.values()
        assert "SLOAD" in OPCODES.values()
