import pytest
from decompiler.analysis.context_builder import create_context, merge_contexts
from decompiler.core.instruction import Instruction
from decompiler.core.transactional_context import TransactionalContext

def test_create_context_basics():
    """Test basic context creation."""
    # Create a simple instruction
    instr = Instruction(offset=0x10, opcode="ADD")
    
    # Create a context for this instruction with empty initial context
    ctx = create_context(instr, {}, {})
    
    # Verify that a context was created
    assert ctx is not None
    assert isinstance(ctx, TransactionalContext)
    
    # Check if the instruction trace was updated
    assert "instruction_trace" in ctx
    assert 0x10 in ctx.get("instruction_trace")

def test_context_for_jump():
    """Test context creation for jump instructions."""
    # Create a jump instruction
    jump_instr = Instruction(offset=0x20, opcode="JUMP")
    
    # Jump classifications
    jump_classifications = {0x20: "private-call"}
    
    # Create a context for this instruction
    ctx = create_context(jump_instr, TransactionalContext(), jump_classifications)
    
    # Verify the function call was tracked
    assert ctx.get_call_depth() == 1  # Should have entered a function
    assert ctx.get("last_call_offset") == 0x20

def test_context_for_jumpi():
    """Test context creation for conditional jump instructions."""
    # Create a conditional jump instruction
    jumpi_instr = Instruction(offset=0x30, opcode="JUMPI")
    
    # Create a context for this instruction
    ctx = create_context(jumpi_instr, TransactionalContext(), {})
    
    # Verify that branch tracking was updated
    assert ctx.get("current_branch_id") == 1

def test_context_for_return():
    """Test context creation for return jumps."""
    # Create initial context with a function call
    initial_ctx = TransactionalContext()
    initial_ctx.enter_function()
    initial_ctx.set("last_call_offset", 0x40)
    
    # Create a return jump instruction
    return_instr = Instruction(offset=0x50, opcode="JUMP")
    
    # Jump classifications indicating this is a return
    jump_classifications = {0x50: "private-return"}
    
    # Create a context for this instruction
    ctx = create_context(return_instr, initial_ctx, jump_classifications)
    
    # Verify function return was tracked
    assert ctx.get_call_depth() == 0  # Should have exited the function
    
    # Check that function return was recorded
    function_returns = ctx.get("function_returns", {})
    assert 0x40 in function_returns
    assert function_returns[0x40] == 0x50

def test_context_instruction_trace():
    """Test instruction trace in context."""
    ctx = TransactionalContext()
    
    # Add several instructions to the trace
    for i in range(10):
        instr = Instruction(offset=i*0x10, opcode="PUSH1")
        ctx = create_context(instr, ctx, {})
    
    # Check that all instructions are in the trace in correct order
    trace = ctx.get("instruction_trace")
    assert len(trace) == 10
    for i, offset in enumerate(trace):
        assert offset == i*0x10

def test_context_trace_limit():
    """Test that instruction trace is limited to prevent unbounded growth."""
    ctx = TransactionalContext()
    
    # Set a synthetic instruction trace that's already near the limit
    initial_trace = list(range(95))
    ctx.set("instruction_trace", initial_trace)
    
    # Add more instructions to exceed the limit (100)
    for i in range(10):
        instr = Instruction(offset=100+i, opcode="PUSH1")
        ctx = create_context(instr, ctx, {})
    
    # Check that the trace is limited to 100 items
    trace = ctx.get("instruction_trace")
    assert len(trace) == 100
    
    # Verify it contains the most recent instructions (newest items are appended)
    assert trace[-1] == 109
    assert trace[-10] == 100

def test_merge_contexts():
    """Test merging two contexts."""
    # Create two contexts with different properties
    ctx1 = TransactionalContext()
    ctx1.set("key1", "value1")
    ctx1.enter_function()  # depth = 1
    ctx1.set("function_returns", {0x10: 0x20})
    ctx1.set("instruction_trace", [1, 2, 3])
    
    ctx2 = TransactionalContext()
    ctx2.set("key2", "value2")
    ctx2.set("function_returns", {0x30: 0x40})
    ctx2.set("instruction_trace", [4, 5, 6, 7])
    # No function call in ctx2, so depth = 0
    
    # Merge the contexts
    merged = merge_contexts(ctx1, ctx2)
    
    # Check function depth (should take minimum which is 0)
    assert merged.get_call_depth() == 0
    
    # Check merged function returns
    returns = merged.get("function_returns", {})
    assert 0x10 in returns
    assert 0x30 in returns
    assert returns[0x10] == 0x20
    assert returns[0x30] == 0x40
    
    # Check instruction trace (should take longer one)
    trace = merged.get("instruction_trace")
    assert len(trace) == 4
    assert trace == [4, 5, 6, 7]
