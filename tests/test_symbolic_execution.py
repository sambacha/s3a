import pytest
import z3
from decompiler.analysis.symbolic_executor import SymbolicExecutor, ExecutionState, SymbolicValue
from decompiler.core.basic_block import BasicBlock
from decompiler.core.instruction import Instruction
from decompiler.analysis.jump_classifier import classify_jumps
from decompiler.utils.evm_ops import *

class MockPyevmInstruction:
    """Mock PyevmInstruction for testing."""
    def __init__(self, pc, size=1):
        self.pc = pc
        self._size = size
        
    def size(self):
        return self._size

def test_symbolic_value_basic():
    """Test basic SymbolicValue functionality."""
    # Test concrete value
    v1 = SymbolicValue(value=42)
    assert v1.is_symbolic == False
    assert v1.get_concrete_value() == 42
    
    # Test symbolic value
    v2 = SymbolicValue()
    assert v2.is_symbolic == True
    assert v2.get_concrete_value() is None

def test_symbolic_value_operations():
    """Test SymbolicValue operations."""
    v1 = SymbolicValue(value=10)
    v2 = SymbolicValue(value=5)
    
    # Test arithmetic operations
    result = v1.add(v2)
    assert result.get_concrete_value() == 15
    
    result = v1.sub(v2)
    assert result.get_concrete_value() == 5
    
    result = v1.mul(v2)
    assert result.get_concrete_value() == 50
    
    result = v1.div(v2)
    assert result.get_concrete_value() == 2
    
    # Test comparison operations
    result = v1.lt(v2)
    assert result.get_concrete_value() == 0
    
    result = v2.lt(v1)
    assert result.get_concrete_value() == 1

def test_execution_state():
    """Test ExecutionState functionality."""
    state = ExecutionState()
    
    # Test push and pop
    state.push(10)
    state.push(20)
    
    assert len(state.stack) == 2
    assert state.peek().get_concrete_value() == 20
    assert state.peek(1).get_concrete_value() == 10
    
    val = state.pop()
    assert val.get_concrete_value() == 20
    assert len(state.stack) == 1

def test_execute_block_simple():
    """Test executing a simple block."""
    # Create a simple block with PUSH1 10, PUSH1 20, ADD
    block = BasicBlock(start_offset=0, end_offset=5)
    
    push1 = Instruction(offset=0, opcode="PUSH1", operands=[10])
    push2 = Instruction(offset=2, opcode="PUSH1", operands=[20])
    add = Instruction(offset=4, opcode="ADD")
    
    block.instructions = [push1, push2, add]
    
    # Create a mock instruction map
    instr_map_raw = {
        0: MockPyevmInstruction(pc=0, size=2),
        2: MockPyevmInstruction(pc=2, size=2),
        4: MockPyevmInstruction(pc=4, size=1)
    }
    
    # Execute the block
    executor = SymbolicExecutor({0: block}, instr_map_raw)
    initial_state = ExecutionState()
    
    final_state = executor.execute_block_symbolically(block, initial_state)
    
    # Check result: stack should have one item with value 30
    assert len(final_state.stack) == 1
    assert final_state.stack[0].get_concrete_value() == 30

def test_jump_target_analysis():
    """Test analyzing jump targets."""
    # Create a block with: PUSH1 0x10, JUMP
    block = BasicBlock(start_offset=0, end_offset=3)
    
    push = Instruction(offset=0, opcode="PUSH1", operands=[0x10])
    jump = Instruction(offset=2, opcode="JUMP")
    
    block.instructions = [push, jump]
    
    # Create a mock instruction map
    instr_map_raw = {
        0: MockPyevmInstruction(pc=0, size=2),
        2: MockPyevmInstruction(pc=2, size=1)
    }
    
    # Analyze jump target
    executor = SymbolicExecutor({0: block}, instr_map_raw)
    initial_state = ExecutionState()
    
    concrete_target, symbolic_expr = executor.analyze_jump(jump, initial_state)
    
    # Check that we resolved the target correctly
    assert concrete_target == 0x10
    assert symbolic_expr is None

def test_complex_jump_classification():
    """Test classifying different types of jumps."""
    # Create several blocks with different jump patterns
    
    # Block 1: Simple direct jump (PUSH target, JUMP) - intra-procedural
    block1 = BasicBlock(start_offset=0, end_offset=3)
    block1.instructions = [
        Instruction(offset=0, opcode="PUSH1", operands=[0x10]),
        Instruction(offset=2, opcode="JUMP")
    ]
    
    # Block 2: Conditional jump - intra-procedural
    block2 = BasicBlock(start_offset=10, end_offset=15)
    block2.instructions = [
        Instruction(offset=10, opcode="PUSH1", operands=[0x20]),
        Instruction(offset=12, opcode="ISZERO"),
        Instruction(offset=13, opcode="JUMPI")
    ]
    
    # Block 3: Function call pattern - private-call
    block3 = BasicBlock(start_offset=20, end_offset=27)
    block3.instructions = [
        Instruction(offset=20, opcode="PUSH1", operands=[42]),  # arg
        Instruction(offset=22, opcode="PUSH1", operands=[0x30]),  # return address
        Instruction(offset=24, opcode="PUSH1", operands=[0x40]),  # function address
        Instruction(offset=26, opcode="JUMP")
    ]
    
    # Target blocks
    jumpdest1 = BasicBlock(start_offset=0x10, end_offset=0x11)
    jumpdest1.instructions = [Instruction(offset=0x10, opcode="JUMPDEST")]
    
    jumpdest2 = BasicBlock(start_offset=0x20, end_offset=0x21)
    jumpdest2.instructions = [Instruction(offset=0x20, opcode="JUMPDEST")]
    
    function_entry = BasicBlock(start_offset=0x40, end_offset=0x41)
    function_entry.instructions = [Instruction(offset=0x40, opcode="JUMPDEST")]
    
    # Set up successors for blocks
    block1.successors = [jumpdest1]
    block2.successors = [jumpdest2]
    block3.successors = [function_entry]
    
    # Set up predecessors
    jumpdest1.predecessors = [block1]
    jumpdest2.predecessors = [block2]
    function_entry.predecessors = [block3]
    
    # Create a mock instruction map
    instr_map_raw = {
        0: MockPyevmInstruction(pc=0, size=2),
        2: MockPyevmInstruction(pc=2, size=1),
        10: MockPyevmInstruction(pc=10, size=2),
        12: MockPyevmInstruction(pc=12, size=1),
        13: MockPyevmInstruction(pc=13, size=1),
        20: MockPyevmInstruction(pc=20, size=2),
        22: MockPyevmInstruction(pc=22, size=2),
        24: MockPyevmInstruction(pc=24, size=2),
        26: MockPyevmInstruction(pc=26, size=1),
        0x10: MockPyevmInstruction(pc=0x10, size=1),
        0x20: MockPyevmInstruction(pc=0x20, size=1),
        0x40: MockPyevmInstruction(pc=0x40, size=1)
    }
    
    # Set up blocks dictionary
    blocks = {
        0: block1,
        10: block2,
        20: block3,
        0x10: jumpdest1,
        0x20: jumpdest2,
        0x40: function_entry
    }
    
    # Set up jumps
    jumps = {
        2: block1.instructions[1],   # JUMP at offset 2
        13: block2.instructions[2],  # JUMPI at offset 13
        26: block3.instructions[3]   # JUMP at offset 26 (function call)
    }
    
    # Analyze jump targets
    executor = SymbolicExecutor(blocks, instr_map_raw)
    
    # Create mock stack analysis results
    stack_analysis = {
        2: {"locally_resolved": True, "unique_target": True, "escaping_dest": False, "concrete_target": 0x10},
        13: {"locally_resolved": True, "unique_target": True, "escaping_dest": False, "concrete_target": 0x20},
        26: {"locally_resolved": True, "unique_target": True, "escaping_dest": True, "concrete_target": 0x40}
    }
    
    # Classify jumps
    classifications = classify_jumps(jumps, blocks, stack_analysis)
    
    # Check classifications
    assert classifications[2] == "intra-procedural"
    assert classifications[13] == "intra-procedural"
    assert classifications[26] == "private-call"
