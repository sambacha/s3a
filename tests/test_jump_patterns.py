import pytest
from decompiler.analysis.jump_patterns import identify_jump_patterns, find_function_entry_patterns, analyze_block_relationships
from decompiler.core.basic_block import BasicBlock
from decompiler.core.instruction import Instruction

def create_test_block(start_offset, instructions):
    """Helper to create a test basic block."""
    if instructions:
        end_offset = instructions[-1].offset
    else:
        end_offset = start_offset
    block = BasicBlock(start_offset=start_offset, end_offset=end_offset)
    block.instructions = instructions
    return block

def test_identify_direct_jump_pattern():
    """Test identification of direct jump pattern."""
    # Create a block with PUSH1 target, JUMP
    instructions = [
        Instruction(offset=0x10, opcode="PUSH1", operands=[0x20]),
        Instruction(offset=0x12, opcode="JUMP")
    ]
    block = create_test_block(0x10, instructions)
    
    # Setup test environment
    blocks = {0x10: block}
    jumps = {0x12: instructions[1]}
    
    # Run pattern analysis
    patterns = identify_jump_patterns(jumps, blocks)
    
    # Check results
    assert 0x12 in patterns
    assert patterns[0x12]["pattern"] == "direct_jump"
    assert patterns[0x12]["confidence"] > 0.5
    assert patterns[0x12]["metadata"]["target"] == 0x20

def test_identify_function_call_pattern():
    """Test identification of function call pattern."""
    # Create a block with function call pattern
    instructions = [
        Instruction(offset=0x30, opcode="PUSH1", operands=[42]),  # Argument
        Instruction(offset=0x32, opcode="DUP1"),                 # Stack manipulation
        Instruction(offset=0x33, opcode="PUSH1", operands=[0x40]), # Target
        Instruction(offset=0x35, opcode="JUMP")
    ]
    block = create_test_block(0x30, instructions)
    
    # Setup test environment
    blocks = {0x30: block}
    jumps = {0x35: instructions[3]}
    
    # Run pattern analysis
    patterns = identify_jump_patterns(jumps, blocks)
    
    # Check results
    assert 0x35 in patterns
    assert patterns[0x35]["pattern"] == "function_call"
    assert patterns[0x35]["metadata"]["target"] == 0x40

def test_identify_conditional_branch_pattern():
    """Test identification of conditional branch pattern."""
    # Create a block with conditional branch pattern
    instructions = [
        Instruction(offset=0x50, opcode="PUSH1", operands=[0x60]),  # Target
        Instruction(offset=0x52, opcode="ISZERO"),                 # Condition
        Instruction(offset=0x53, opcode="JUMPI")
    ]
    block = create_test_block(0x50, instructions)
    
    # Setup test environment
    blocks = {0x50: block}
    jumps = {0x53: instructions[2]}
    
    # Run pattern analysis
    patterns = identify_jump_patterns(jumps, blocks)
    
    # Check results
    assert 0x53 in patterns
    assert patterns[0x53]["pattern"] == "conditional_branch"

def test_identify_function_return_pattern():
    """Test identification of function return pattern."""
    # Create a block with function return pattern (contains SWAP to restore stack)
    instructions = [
        Instruction(offset=0x70, opcode="SWAP1"),   # Restore stack
        Instruction(offset=0x71, opcode="POP"),     # Clean stack
        Instruction(offset=0x72, opcode="JUMP")     # Return jump
    ]
    block = create_test_block(0x70, instructions)
    
    # Setup test environment
    blocks = {0x70: block}
    jumps = {0x72: instructions[2]}
    
    # Run pattern analysis
    patterns = identify_jump_patterns(jumps, blocks)
    
    # Check results
    assert 0x72 in patterns
    assert patterns[0x72]["pattern"] == "function_return"
    assert patterns[0x72]["metadata"]["has_swap"] == True

def test_find_function_entry_patterns():
    """Test identification of function entry points."""
    # Create function entry block (JUMPDEST followed by stack manipulation)
    entry_instructions = [
        Instruction(offset=0x80, opcode="JUMPDEST"),
        Instruction(offset=0x81, opcode="SWAP1"),    # Manipulate args
        Instruction(offset=0x82, opcode="POP")
    ]
    entry_block = create_test_block(0x80, entry_instructions)
    entry_block.predecessors = [object(), object()]  # Multiple predecessors
    
    # Create a regular JUMPDEST block without stack manipulation
    normal_instructions = [
        Instruction(offset=0x90, opcode="JUMPDEST"),
        Instruction(offset=0x91, opcode="PUSH1", operands=[0]),
    ]
    normal_block = create_test_block(0x90, normal_instructions)
    normal_block.predecessors = [object()]  # Only one predecessor
    
    # Setup test environment
    blocks = {
        0x80: entry_block,
        0x90: normal_block
    }
    
    # Run function entry analysis
    entries = find_function_entry_patterns(blocks)
    
    # Check results
    assert 0x80 in entries  # Should be identified (has stack manipulation and multiple preds)
    assert 0x90 not in entries  # Should not be identified

def test_analyze_block_relationships():
    """Test analysis of relationships between blocks."""
    # Create function entry blocks
    entry1 = create_test_block(0xA0, [Instruction(offset=0xA0, opcode="JUMPDEST")])
    entry1.predecessors = [object(), object()]  # Multiple predecessors
    
    # Create shared blocks (multiple predecessors but not function entries)
    shared = create_test_block(0xB0, [Instruction(offset=0xB0, opcode="ADD")])
    shared.predecessors = [object(), object()]  # Multiple predecessors
    
    # Create exit blocks
    exit1 = create_test_block(
        0xC0, 
        [
            Instruction(offset=0xC0, opcode="PUSH1", operands=[0]),
            Instruction(offset=0xC2, opcode="RETURN")
        ]
    )
    
    exit2 = create_test_block(
        0xD0, 
        [
            Instruction(offset=0xD0, opcode="REVERT")
        ]
    )
    
    # Setup test environment
    blocks = {
        0xA0: entry1,
        0xB0: shared,
        0xC0: exit1,
        0xD0: exit2
    }
    
    # Run block relationship analysis
    relationships = analyze_block_relationships(blocks)
    
    # Check results
    assert 0xA0 in relationships["function_entries"]
    assert 0xB0 in relationships["shared_blocks"]
    assert 0xC0 in relationships["exit_blocks"]
    assert 0xD0 in relationships["exit_blocks"]
