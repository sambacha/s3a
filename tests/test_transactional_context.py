import pytest
from decompiler.core.transactional_context import TransactionalContext

def test_context_basics():
    """Test basic functionality of TransactionalContext."""
    ctx = TransactionalContext()
    
    # Test storage and retrieval
    ctx.set("test_key", "test_value")
    assert ctx.get("test_key") == "test_value"
    assert ctx.get("nonexistent_key") is None
    assert ctx.get("nonexistent_key", "default") == "default"
    
    # Test contains
    assert "test_key" in ctx
    assert "nonexistent_key" not in ctx
    
    # Test iterators
    ctx.set("another_key", "another_value")
    keys = list(ctx.keys())
    assert "test_key" in keys
    assert "another_key" in keys
    
    values = list(ctx.values())
    assert "test_value" in values
    assert "another_value" in values
    
    # Test items
    items = dict(ctx.items())
    assert items["test_key"] == "test_value"
    assert items["another_key"] == "another_value"

def test_context_clone():
    """Test cloning contexts."""
    ctx1 = TransactionalContext()
    ctx1.set("key1", "value1")
    ctx1.enter_function()  # Call depth = 1
    
    # Clone the context
    ctx2 = ctx1.clone()
    
    # Verify clone has the same values
    assert ctx2.get("key1") == "value1"
    assert ctx2.get_call_depth() == 1
    
    # Modify the clone and verify it doesn't affect the original
    ctx2.set("key2", "value2")
    ctx2.exit_function()  # Call depth = 0
    
    assert ctx1.get("key2") is None  # Original shouldn't have the new key
    assert ctx1.get_call_depth() == 1  # Original call depth should be unchanged

def test_function_depth_tracking():
    """Test function call depth tracking."""
    ctx = TransactionalContext()
    assert ctx.get_call_depth() == 0  # Initial depth should be 0
    
    # Test entering function calls
    for i in range(1, 5):
        ctx.enter_function()
        assert ctx.get_call_depth() == i
    
    # Test exiting function calls
    for i in range(3, -1, -1):
        ctx.exit_function()
        assert ctx.get_call_depth() == i
    
    # Test that depth doesn't go below 0
    ctx.exit_function()
    assert ctx.get_call_depth() == 0
    
    # Test that depth doesn't exceed max_private_depth
    max_depth = ctx.max_private_depth
    for _ in range(max_depth + 5):
        ctx.enter_function()
    assert ctx.get_call_depth() == max_depth
    
    # Test direct depth setting
    ctx.set_call_depth(3)
    assert ctx.get_call_depth() == 3
    
    # Test bounds checking in set_call_depth
    ctx.set_call_depth(-1)
    assert ctx.get_call_depth() == 0
    
    ctx.set_call_depth(max_depth + 10)
    assert ctx.get_call_depth() == max_depth

def test_merge_function():
    """Test merging calls into private context."""
    ctx = TransactionalContext()
    
    # Add calls to private context
    ctx.merge("call1")
    ctx.merge("call2")
    
    assert "call1" in ctx.private_ctx
    assert "call2" in ctx.private_ctx
    
    # Test duplicate call handling
    ctx.merge("call1")  # Should not add again
    assert ctx.private_ctx.count("call1") == 1
    
    # Test depth limit
    original_max = ctx.max_private_depth
    ctx.max_private_depth = 3
    
    ctx.merge("call3")
    assert len(ctx.private_ctx) == 3
    
    # This should not be added due to depth limit
    ctx.merge("call4")
    assert len(ctx.private_ctx) == 3
    assert "call4" not in ctx.private_ctx
    
    # Restore max depth
    ctx.max_private_depth = original_max
