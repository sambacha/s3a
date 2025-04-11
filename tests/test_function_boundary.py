import pytest
from decompiler.analysis.function_boundary import (
    find_return_instructions,
    find_call_sites,
    match_call_to_returns,
    create_function_objects,
    identify_function_blocks,
    infer_function_boundaries
)
from decompiler.core.basic_block import BasicBlock
from decompiler.core.instruction import Instruction
from decompiler.core.function import Function

def create_test_block(start_offset, end_offset, instructions):
    """Helper to create a test basic block."""
    block = BasicBlock(start_offset=start_offset, end_offset=end_offset)
    block.instructions = instructions
    block.predecessors = []
    block.successors = []
    return block

def test_find_return_instructions():
    """Test finding return instructions based on jump classifications."""
    # Create some jump instructions
    jump1 = Instruction(offset=0x10, opcode="JUMP")
    jump2 = Instruction(offset=0x20, opcode="JUMP")
    jump3 = Instruction(offset=0x30, opcode="JUMP")
    
    # Create jump dictionary
    jumps = {
        0x10: jump1,
        0x20: jump2,
        0x30: jump3
    }
    
    # Create jump classifications
    jump_classifications = {
        0x10: "intra-procedural",
        0x20: "private-return",
        0x30: "private-return"
    }
    
    # Find return instructions
    returns = find_return_instructions(jumps, jump_classifications)
    
    # Check results
    assert len(returns) == 2
    assert jump2 in returns
    assert jump3 in returns
    assert jump1 not in returns

def test_find_call_sites():
    """Test finding call sites based on jump classifications."""
    # Create some jump instructions with preceding PUSH instructions
    block1 = create_test_block(
        0x10, 0x13,
        [
            Instruction(offset=0x10, opcode="PUSH1", operands=[0x40]),
            Instruction(offset=0x12, opcode="JUMP")
        ]
    )
    
    block2 = create_test_block(
        0x20, 0x22,
        [
            Instruction(offset=0x20, opcode="PUSH1", operands=[0x50]),
            Instruction(offset=0x22, opcode="JUMP")
        ]
    )
    
    # Jump with no target constant
    block3 = create_test_block(
        0x30, 0x31,
        [
            Instruction(offset=0x30, opcode="SWAP1"),
            Instruction(offset=0x31, opcode="JUMP")
        ]
    )
    
    # Create jump dictionary
    jumps = {
        0x12: block1.instructions[1],
        0x22: block2.instructions[1],
        0x31: block3.instructions[1]
    }
    
    # Create jump classifications
    jump_classifications = {
        0x12: "private-call",
        0x22: "private-call",
        0x31: "private-return"
    }
    
    # Create blocks dictionary
    blocks = {
        0x10: block1,
        0x20: block2,
        0x30: block3
    }
    
    # Find call sites
    call_sites = find_call_sites(jumps, jump_classifications, blocks)
    
    # Check results
    assert len(call_sites) == 2
    
    # Check that targets were correctly identified
    call_targets = {target for _, target in call_sites}
    assert 0x40 in call_targets
    assert 0x50 in call_targets

def test_match_call_to_returns():
    """Test matching call sites to return instructions."""
    # Create some call sites
    call_sites = [
        (Instruction(offset=0x10, opcode="JUMP"), 0x40),
        (Instruction(offset=0x20, opcode="JUMP"), 0x50)
    ]
    
    # Create return instructions in target blocks
    return1 = Instruction(offset=0x45, opcode="JUMP")
    return2 = Instruction(offset=0x55, opcode="JUMP")
    returns = [return1, return2]
    
    # Create blocks
    block1 = create_test_block(
        0x40, 0x45,
        [
            Instruction(offset=0x40, opcode="JUMPDEST"),
            Instruction(offset=0x41, opcode="PUSH1", operands=[0]),
            return1
        ]
    )
    
    block2 = create_test_block(
        0x50, 0x55,
        [
            Instruction(offset=0x50, opcode="JUMPDEST"),
            Instruction(offset=0x51, opcode="PUSH1", operands=[0]),
            return2
        ]
    )
    
    # Create blocks dictionary
    blocks = {
        0x40: block1,
        0x50: block2
    }
    
    # Match calls to returns
    pairs = match_call_to_returns(call_sites, returns, blocks)
    
    # Check results
    assert len(pairs) == 2
    
    # Find pair for first call
    pair1 = next((p for p in pairs if p["call"].offset == 0x10), None)
    assert pair1 is not None
    assert pair1["target"] == 0x40
    assert len(pair1["returns"]) == 1
    assert pair1["returns"][0].offset == 0x45
    
    # Find pair for second call
    pair2 = next((p for p in pairs if p["call"].offset == 0x20), None)
    assert pair2 is not None
    assert pair2["target"] == 0x50
    assert len(pair2["returns"]) == 1
    assert pair2["returns"][0].offset == 0x55

def test_create_function_objects():
    """Test creating Function objects from call/return pairs."""
    # Create some blocks
    entry1 = create_test_block(
        0x40, 0x41,
        [Instruction(offset=0x40, opcode="JUMPDEST")]
    )
    
    exit1 = create_test_block(
        0x45, 0x46,
        [Instruction(offset=0x45, opcode="JUMP")]
    )
    
    entry2 = create_test_block(
        0x50, 0x51,
        [Instruction(offset=0x50, opcode="JUMPDEST")]
    )
    
    # Create call/return pairs
    pairs = [
        {
            "call": Instruction(offset=0x10, opcode="JUMP"),
            "target": 0x40,
            "returns": [Instruction(offset=0x45, opcode="JUMP")]
        },
        {
            "call": Instruction(offset=0x20, opcode="JUMP"),
            "target": 0x50,
            "returns": []
        }
    ]
    
    # Create blocks dictionary
    blocks = {
        0x40: entry1,
        0x45: exit1,
        0x50: entry2
    }
    
    # Create jump classifications
    jump_classifications = {
        0x10: "private-call",
        0x20: "private-call",
        0x45: "private-return"
    }
    
    # Create Function objects
    jumps = {
        0x10: Instruction(offset=0x10, opcode="JUMP"),
        0x20: Instruction(offset=0x20, opcode="JUMP"),
        0x45: Instruction(offset=0x45, opcode="JUMP")
    }
    
    functions = create_function_objects(pairs, blocks, jumps, jump_classifications)
    
    # Check results
    assert len(functions) == 2
    assert 0x40 in functions
    assert 0x50 in functions
    
    # Check function attributes
    assert functions[0x40].entry_block == entry1
    assert len(functions[0x40].exit_blocks) == 1
    assert functions[0x40].exit_blocks[0] == exit1

def test_identify_function_blocks():
    """Test identifying blocks belonging to a function."""
    # Create a graph of blocks for a function
    entry = create_test_block(
        0x40, 0x41,
        [Instruction(offset=0x40, opcode="JUMPDEST")]
    )
    
    block1 = create_test_block(
        0x42, 0x43,
        [Instruction(offset=0x42, opcode="ADD")]
    )
    
    block2 = create_test_block(
        0x44, 0x45,
        [Instruction(offset=0x44, opcode="MUL")]
    )
    
    exit = create_test_block(
        0x46, 0x47,
        [Instruction(offset=0x46, opcode="JUMP")]
    )
    
    # Different function's block (should not be included)
    other_func = create_test_block(
        0x50, 0x51,
        [Instruction(offset=0x50, opcode="JUMPDEST")]
    )
    
    # Set up successors and predecessors
    entry.successors = [block1, block2]
    block1.predecessors = [entry]
    block1.successors = [exit]
    block2.predecessors = [entry]
    block2.successors = [exit]
    exit.predecessors = [block1, block2]
    
    # Create blocks dictionary
    blocks = {
        0x40: entry,
        0x42: block1,
        0x44: block2,
        0x46: exit,
        0x50: other_func
    }
    
    # Jump classifications
    jump_classifications = {
        0x46: "private-return"
    }
    
    # Identify function blocks
    function_blocks = identify_function_blocks(entry, blocks, jump_classifications)
    
    # Check results
    assert len(function_blocks) == 4
    assert entry in function_blocks
    assert block1 in function_blocks
    assert block2 in function_blocks
    assert exit in function_blocks
    assert other_func not in function_blocks

def test_infer_function_boundaries():
    """Integration test for function boundary inference."""
    # Create a simple program with a main function and a callee
    
    # Main function (calling another function)
    main_entry = create_test_block(
        0x00, 0x01,
        [Instruction(offset=0x00, opcode="PUSH1", operands=[0x20])]
    )
    
    main_call = create_test_block(
        0x02, 0x04,
        [
            Instruction(offset=0x02, opcode="PUSH1", operands=[0x10]),  # Return address
            Instruction(offset=0x04, opcode="PUSH1", operands=[0x30]),  # Function address
            Instruction(offset=0x06, opcode="JUMP")                    # Call jump
        ]
    )
    
    main_return = create_test_block(
        0x10, 0x11,
        [
            Instruction(offset=0x10, opcode="JUMPDEST"),  # Return landing
            Instruction(offset=0x11, opcode="STOP")       # End of program
        ]
    )
    
    # Called function
    func_entry = create_test_block(
        0x30, 0x31,
        [
            Instruction(offset=0x30, opcode="JUMPDEST"),  # Function entry
            Instruction(offset=0x31, opcode="PUSH1", operands=[0]),
        ]
    )
    
    func_exit = create_test_block(
        0x32, 0x33,
        [
            Instruction(offset=0x32, opcode="SWAP1"),     # Prepare for return
            Instruction(offset=0x33, opcode="JUMP")       # Return jump
        ]
    )
    
    # Set up block connectivity
    main_entry.successors = [main_call]
    main_call.predecessors = [main_entry]
    main_call.successors = [func_entry]  # Call edge
    main_return.predecessors = [func_exit]  # Return target
    
    func_entry.predecessors = [main_call]
    func_entry.successors = [func_exit]
    func_exit.predecessors = [func_entry]
    func_exit.successors = [main_return]  # Return edge
    
    # Set up blocks dictionary
    blocks = {
        0x00: main_entry,
        0x02: main_call,
        0x10: main_return,
        0x30: func_entry,
        0x32: func_exit
    }
    
    # Set up jump dictionary
    jumps = {
        0x06: main_call.instructions[2],  # Call jump
        0x33: func_exit.instructions[1]   # Return jump
    }
    
    # Jump classifications
    jump_classifications = {
        0x06: "private-call",
        0x33: "private-return"
    }
    
    # Infer function boundaries
    functions = infer_function_boundaries(jumps, blocks, jump_classifications, {})
    
    # Check results
    assert len(functions) >= 1
    assert 0x30 in functions  # Should identify the called function
    
    # Check that the function has correct blocks
    if 0x30 in functions:
        func = functions[0x30]
        func_blocks = func.blocks
        assert len(func_blocks) == 2
        assert func_entry in func_blocks
        assert func_exit in func_blocks
        
        # Check entry and exit blocks
        assert func.entry_block == func_entry
        assert len(func.exit_blocks) >= 1
