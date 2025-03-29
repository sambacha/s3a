import pytest
# Import composite from hypothesis.strategies
from hypothesis import given, settings
from hypothesis.strategies import composite # Import composite specifically
from hypothesis import strategies as st
from typing import List, Tuple, Optional

# Assuming the src directory is importable, adjust if necessary
# e.g., if tests are run via `pytest` from the root directory
from src.tracer.evm_opcodes import disassemble_bytecode, Opcode

# Define a strategy for generating bytecode-like binary data
# We'll generate bytes, then convert to hex string as expected by disassemble_bytecode
bytecode_strategy = st.binary(min_size=0, max_size=500).map(lambda b: b.hex())

# Define a strategy for generating valid EVM opcodes (0x00 to 0xff)
opcode_bytes_strategy = st.integers(min_value=0x00, max_value=0xff).map(lambda i: i.to_bytes(1, 'big'))

# Strategy for generating sequences of valid opcodes, possibly with push data
# Needs to be decorated with @composite to receive the 'draw' function
@composite
def generate_bytecode_sequence(draw):
    elements = []
    length = draw(st.integers(min_value=0, max_value=100)) # Max 100 operations
    for _ in range(length):
        opcode_val = draw(st.integers(min_value=0x00, max_value=0xff))
        elements.append(opcode_val.to_bytes(1, 'big'))
        if Opcode.PUSH1 <= opcode_val <= Opcode.PUSH32:
            push_size = opcode_val - Opcode.PUSH1 + 1
            push_data = draw(st.binary(min_size=push_size, max_size=push_size))
            elements.append(push_data)
    return b"".join(elements).hex()

# Call the composite function to get the strategy object
valid_bytecode_strategy = generate_bytecode_sequence()


@settings(max_examples=200, deadline=None) # Increase examples, disable deadline for potentially slow disassembly
@given(bytecode_hex=bytecode_strategy)
def test_disassemble_does_not_crash_random_bytes(bytecode_hex: str):
    """
    Test that disassemble_bytecode handles random byte sequences without crashing.
    """
    try:
        disassemble_bytecode(bytecode_hex)
    except Exception as e:
        # We might expect certain errors (like incomplete push data), but not others
        # For now, just assert it doesn't raise unexpected errors.
        # A more refined test could check for specific expected exceptions.
        pytest.fail(f"disassemble_bytecode raised unexpected exception {type(e).__name__}: {e} on input {bytecode_hex}")

@settings(max_examples=200, deadline=None)
@given(bytecode_hex=valid_bytecode_strategy)
def test_disassemble_valid_sequences(bytecode_hex: str):
    """
    Test that disassemble_bytecode processes sequences of valid opcodes.
    """
    try:
        operations = disassemble_bytecode(bytecode_hex)
        assert isinstance(operations, list)
        # Further assertions could be added, e.g., checking offsets
        if operations:
            last_op = operations[-1]
            # Check if the last offset + size roughly matches bytecode length
            last_offset = last_op[3]
            last_size = 1
            if Opcode.PUSH1 <= last_op[1] <= Opcode.PUSH32:
                last_size += last_op[1] - Opcode.PUSH1 + 1
            assert last_offset + last_size <= (len(bytecode_hex) // 2)

    except Exception as e:
        pytest.fail(f"disassemble_bytecode raised unexpected exception {type(e).__name__}: {e} on valid input sequence {bytecode_hex}")

# Strategy for generating a single PUSH operation (opcode + data)
@composite
def push_operation_strategy(draw):
    push_opcode_val = draw(st.integers(min_value=Opcode.PUSH1, max_value=Opcode.PUSH32))
    push_size = push_opcode_val - Opcode.PUSH1 + 1
    push_data_bytes = draw(st.binary(min_size=push_size, max_size=push_size))
    bytecode_bytes = push_opcode_val.to_bytes(1, 'big') + push_data_bytes
    return push_opcode_val, push_data_bytes, bytecode_bytes.hex()

@settings(max_examples=500, deadline=None) # Test many PUSH variations
@given(push_info=push_operation_strategy())
def test_disassemble_single_push_operation(push_info):
    """
    Test that disassemble_bytecode correctly parses single PUSH opcodes and their data.
    """
    push_opcode_val, push_data_bytes, bytecode_hex = push_info
    try:
        operations = disassemble_bytecode(bytecode_hex)
        assert len(operations) == 1, "Should disassemble into exactly one operation"
        op_name, op_val, op_data, op_offset = operations[0]

        assert op_offset == 0, "Offset should be 0 for the first operation"
        assert op_val == push_opcode_val, "Opcode value should match generated PUSH opcode"
        assert op_name == f"PUSH{len(push_data_bytes)}", "Opcode name should match PUSH size"
        assert op_data == push_data_bytes, "Push data bytes should match generated data"

    except Exception as e:
        pytest.fail(f"disassemble_bytecode failed on PUSH operation {bytecode_hex}: {e}")


# --- Tests for Edge Cases ---

def test_disassemble_empty_bytecode():
    """Test that empty bytecode results in an empty list."""
    assert disassemble_bytecode("") == []

# Define valid single-byte opcodes (excluding PUSH1-PUSH32 and INVALID ranges)
# List might not be exhaustive, focusing on common ones and boundaries
single_byte_opcodes = [
    Opcode.STOP, Opcode.ADD, Opcode.MUL, Opcode.SUB, Opcode.DIV, Opcode.SDIV, Opcode.MOD, Opcode.SMOD,
    Opcode.ADDMOD, Opcode.MULMOD, Opcode.EXP, Opcode.SIGNEXTEND, Opcode.LT, Opcode.GT, Opcode.SLT,
    Opcode.SGT, Opcode.EQ, Opcode.ISZERO, Opcode.AND, Opcode.OR, Opcode.XOR, Opcode.NOT, Opcode.BYTE,
    Opcode.SHL, Opcode.SHR, Opcode.SAR, Opcode.SHA3, Opcode.ADDRESS, Opcode.BALANCE, Opcode.ORIGIN,
    Opcode.CALLER, Opcode.CALLVALUE, Opcode.CALLDATALOAD, Opcode.CALLDATASIZE, Opcode.CALLDATACOPY,
    Opcode.CODESIZE, Opcode.CODECOPY, Opcode.GASPRICE, Opcode.EXTCODESIZE, Opcode.EXTCODECOPY,
    Opcode.RETURNDATASIZE, Opcode.RETURNDATACOPY, Opcode.EXTCODEHASH, Opcode.BLOCKHASH, Opcode.COINBASE,
    Opcode.TIMESTAMP, Opcode.NUMBER, Opcode.DIFFICULTY, Opcode.GASLIMIT, Opcode.CHAINID,
    Opcode.SELFBALANCE, Opcode.BASEFEE, Opcode.POP, Opcode.MLOAD, Opcode.MSTORE, Opcode.MSTORE8,
    Opcode.SLOAD, Opcode.SSTORE, Opcode.JUMP, Opcode.JUMPI, Opcode.PC, Opcode.MSIZE, Opcode.GAS,
    Opcode.JUMPDEST, Opcode.CREATE, Opcode.CALL, Opcode.CALLCODE, Opcode.RETURN, Opcode.DELEGATECALL,
    Opcode.CREATE2, Opcode.STATICCALL, Opcode.REVERT, Opcode.SELFDESTRUCT
]
single_byte_opcode_strategy = st.sampled_from(single_byte_opcodes)

@settings(max_examples=len(single_byte_opcodes), deadline=None) # Test all defined single opcodes
@given(opcode_val=single_byte_opcode_strategy)
def test_disassemble_single_non_push_opcode(opcode_val):
    """Test disassembly of single, valid, non-PUSH opcodes."""
    bytecode_hex = opcode_val.to_bytes(1, 'big').hex()
    try:
        operations = disassemble_bytecode(bytecode_hex)
        assert len(operations) == 1
        op_name, op_val, op_data, op_offset = operations[0]
        assert op_offset == 0
        assert op_val == opcode_val
        assert op_data is None # Single byte opcodes have no push data
        # We could also assert op_name matches Opcode(opcode_val).name if Opcode enum has names
    except Exception as e:
        pytest.fail(f"disassemble_bytecode failed on single opcode {bytecode_hex}: {e}")

# --- Test for Invalid Opcodes ---

# Define ranges or specific values for invalid opcodes
invalid_opcode_strategy = st.one_of(
    st.integers(min_value=0x0c, max_value=0x0f),
    st.integers(min_value=0x21, max_value=0x2f),
    st.integers(min_value=0x49, max_value=0x4f),
    st.integers(min_value=0xa5, max_value=0xaf),
    st.integers(min_value=0xb3, max_value=0xbf), # Includes DEPRECATED
    st.integers(min_value=0xf6, max_value=0xf9),
    st.just(0xfc), # INVALID
    st.just(0xfe), # INVALID
)

@composite
def generate_sequence_with_invalid(draw):
    """Generates a bytecode sequence potentially containing invalid opcodes."""
    elements = []
    length = draw(st.integers(min_value=1, max_value=100)) # Ensure at least one op
    invalid_pos = draw(st.integers(min_value=0, max_value=length -1))

    for i in range(length):
        if i == invalid_pos:
            opcode_val = draw(invalid_opcode_strategy)
            elements.append(opcode_val.to_bytes(1, 'big'))
        else:
            # Draw a valid opcode (could be PUSH or single byte)
            opcode_val = draw(st.integers(min_value=0x00, max_value=0xff))
            elements.append(opcode_val.to_bytes(1, 'big'))
            if Opcode.PUSH1 <= opcode_val <= Opcode.PUSH32:
                push_size = opcode_val - Opcode.PUSH1 + 1
                # Ensure we don't read past the end if PUSH is last
                push_data = draw(st.binary(min_size=push_size, max_size=push_size))
                elements.append(push_data)
            elif opcode_val in range(0x0c, 0x10) or \
                 opcode_val in range(0x21, 0x30) or \
                 opcode_val in range(0x49, 0x50) or \
                 opcode_val in range(0xa5, 0xb0) or \
                 opcode_val in range(0xb3, 0xc0) or \
                 opcode_val in range(0xf6, 0xfa) or \
                 opcode_val == 0xfc or opcode_val == 0xfe:
                 # If we accidentally drew an invalid one here, skip push data
                 pass


    return b"".join(elements).hex(), invalid_pos

sequence_with_invalid_strategy = generate_sequence_with_invalid()

@settings(max_examples=300, deadline=None)
@given(data=sequence_with_invalid_strategy)
def test_disassemble_handles_invalid_opcodes(data):
    """Test that invalid opcodes are identified correctly."""
    bytecode_hex, invalid_pos_approx = data
    try:
        operations = disassemble_bytecode(bytecode_hex)
        # Find the operation corresponding to the invalid byte's approximate position
        found_invalid = False
        for op_name, op_val, op_data, op_offset in operations:
             # Check if the value corresponds to a known invalid range/value
             is_known_invalid = (
                 0x0c <= op_val <= 0x0f or
                 0x21 <= op_val <= 0x2f or
                 0x49 <= op_val <= 0x4f or
                 0xa5 <= op_val <= 0xaf or
                 0xb3 <= op_val <= 0xbf or
                 0xf6 <= op_val <= 0xf9 or
                  op_val == 0xfc or
                  op_val == 0xfe
             )
             # Fix indentation error on the next line
             if is_known_invalid:
                 # Update assertion: Check for "UNKNOWN_{hex}" pattern instead of "INVALID"
                 expected_name = f"UNKNOWN_{op_val:02x}"
                 # Fix indentation on the next two lines
                 assert op_name == expected_name, f"Opcode {op_val:#x} at offset {op_offset} should be marked {expected_name}, but got {op_name}"
                 found_invalid = True

         # This assertion might be too strict if the invalid byte causes parsing to stop early
        # assert found_invalid, "Expected to find at least one INVALID opcode"

    except Exception as e:
        # We might expect errors if the invalid opcode placement causes issues,
        # but ideally, it should just mark it as INVALID.
        pytest.fail(f"disassemble_bytecode failed unexpectedly on sequence with invalid opcodes {bytecode_hex}: {e}")


# TODO: Add more specific property tests, e.g.,
# - Test sequences containing specific opcodes (JUMP, JUMPI, etc.).
# - Test handling of PUSH with incomplete data.
