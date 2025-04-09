import pytest  # Assuming pytest might be available or installable later
from decompiler.decompiler import SmartContractDecompiler


def test_simple_addition_bytecode():
    """Tests basic block identification for simple bytecode."""
    bytecode_hex = "6001600201"  # PUSH1 1, PUSH1 2, ADD
    bytecode = bytes.fromhex(bytecode_hex)

    try:
        decompiler = SmartContractDecompiler(bytecode)
    except Exception as e:
        pytest.fail(f"SmartContractDecompiler initialization failed: {e}")

    print(f"\nBytecode: {bytecode_hex}")
    print(f"Number of basic blocks found: {len(decompiler.basic_blocks)}")

    # --- Assertions ---
    assert len(decompiler.basic_blocks) == 1, "Should find exactly one basic block"

    # Check block 0
    assert 0 in decompiler.basic_blocks, "Block starting at offset 0 should exist"
    block_0 = decompiler.basic_blocks[0]

    assert block_0.start_offset == 0, "Block 0 start offset should be 0"
    # The last instruction 'ADD' is at offset 4, so end_offset should be 4
    assert block_0.end_offset == 4, (
        f"Block 0 end offset should be 4, but got {block_0.end_offset}"
    )

    expected_opcodes = ["PUSH1", "PUSH1", "ADD"]
    actual_opcodes = [instr.opcode for instr in block_0.instructions]
    assert len(actual_opcodes) == len(expected_opcodes), (
        f"Block 0 should have {len(expected_opcodes)} instructions"
    )
    assert actual_opcodes == expected_opcodes, (
        f"Block 0 opcodes mismatch: Expected {expected_opcodes}, Got {actual_opcodes}"
    )

    # Check stack analysis (if available)
    # analyze_stack_locally should have been called in __init__
    assert hasattr(block_0, "stack_effect"), (
        "Block 0 should have stack_effect attribute"
    )
    # PUSH1, PUSH1, ADD -> 2 pushes, 1 pop (from ADD consuming 2, pushing 1) -> Net effect: +1
    # Total pushes = 2, Total pops = 2. Stack effect = (pushes, pops)
    # Let's refine the expected stack effect based on analyze_stack_locally logic
    # PUSH1: pushes=1, pops=0
    # PUSH1: pushes=1, pops=0
    # ADD:   pushes=1, pops=2
    # Total: pushes=3, pops=2
    expected_stack_effect = (3, 2)
    assert block_0.stack_effect == expected_stack_effect, (
        f"Block 0 stack effect mismatch: Expected {expected_stack_effect}, Got {block_0.stack_effect}"
    )

    # Check successors/predecessors (should be empty for this simple case)
    assert len(block_0.successors) == 0, "Block 0 should have no successors"
    assert len(block_0.predecessors) == 0, "Block 0 should have no predecessors"

    print("\n--- Test Results ---")
    print(f"Block 0:")
    print(f"  Start: {block_0.start_offset}, End: {block_0.end_offset}")
    print(f"  Instructions ({len(block_0.instructions)}):")
    for instr in block_0.instructions:
        operand_str = f"0x{instr.operands[0]:x}" if instr.operands else ""
        print(f"    0x{instr.offset:x}: {instr.opcode} {operand_str}")
    print(f"  Stack Effect: {block_0.stack_effect}")
    print(f"  Successors: {[b.start_offset for b in block_0.successors]}")
    print(f"  Predecessors: {[b.start_offset for b in block_0.predecessors]}")
    print("--------------------")


# Basic execution block if pytest is not used
if __name__ == "__main__":
    try:
        test_simple_addition_bytecode()
        print("\nSimple addition test PASSED (based on assertions)")
    except AssertionError as e:
        print(f"\nSimple addition test FAILED: {e}")
    except Exception as e:
        print(f"\nTest execution failed with unexpected error: {e}")

# TODO: Add more tests with JUMP, JUMPI, JUMPDEST, multiple blocks etc.
