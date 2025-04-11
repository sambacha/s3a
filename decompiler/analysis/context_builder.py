from ..core.transactional_context import TransactionalContext
from ..core.instruction import Instruction
from typing import Dict, Any, Optional, List, Set

def create_context(instruction: Instruction, current_context: Dict[str, Any], 
                  jump_classifications: Dict[int, str]) -> Dict[str, Any]:
    """
    Create a new context based on the current instruction and context.
    This implements the Merge function that maintains analysis context across
    function boundaries and other control flow constructs.
    
    Args:
        instruction: The current instruction being processed
        current_context: The current analysis context
        jump_classifications: Dictionary mapping jump offsets to classifications

    Returns:
        Updated context dictionary with new state
    """
    # Initialize context if none exists
    if not current_context:
        current_context = TransactionalContext()
    
    # Clone context to avoid modifying the original
    new_context = current_context.clone()
    
    # Get instruction information
    offset = instruction.offset
    opcode = instruction.opcode
    
    # Handle context transitions based on instruction type
    if opcode == "JUMP":
        # Check if this is a function call edge
        if offset in jump_classifications and jump_classifications[offset] == "private-call":
            # Mark context as being in a function call
            new_context.enter_function()
            
            # Store the call offset to match with returns
            new_context.set("last_call_offset", offset)
    
    elif opcode == "JUMPI":
        # For conditional jumps, we're staying in the same function context
        # but typically entering a new control flow branch
        branch_id = new_context.get("current_branch_id", 0) + 1
        new_context.set("current_branch_id", branch_id)
        
        # Store condition information if available
        # Useful for later control flow recovery
        if hasattr(instruction, 'condition'):
            new_context.set(f"branch_{branch_id}_condition", instruction.condition)
    
    # Handle returns from functions
    if offset in jump_classifications and jump_classifications[offset] == "private-return":
        # Get matching call site if available
        call_offset = new_context.get("last_call_offset", None)
        
        if call_offset is not None:
            # Exit the function context
            new_context.exit_function()
            
            # Store information about the return for data flow tracking
            returns = new_context.get("function_returns", {})
            returns[call_offset] = offset
            new_context.set("function_returns", returns)
    
    # Track instruction sequence for context-sensitive analysis
    if "instruction_trace" not in new_context:
        new_context.set("instruction_trace", [])
    
    instruction_trace = new_context.get("instruction_trace")
    
    # Keep the trace bounded to avoid unbounded growth
    if len(instruction_trace) > 100:  # Arbitrary limit
        instruction_trace = instruction_trace[-100:]
    
    instruction_trace.append(offset)
    new_context.set("instruction_trace", instruction_trace)
    
    return new_context

def merge_contexts(ctx1: Dict[str, Any], ctx2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two contexts, used when control flow paths converge.
    
    Args:
        ctx1: First context
        ctx2: Second context
        
    Returns:
        Merged context
    """
    if not ctx1:
        return ctx2
    if not ctx2:
        return ctx1
        
    # Create a base merged context
    merged = ctx1.clone()
    
    # Merge function call information
    function_depth1 = ctx1.get_call_depth() if hasattr(ctx1, 'get_call_depth') else 0
    function_depth2 = ctx2.get_call_depth() if hasattr(ctx2, 'get_call_depth') else 0
    
    # Take the minimum call depth (most conservative)
    if function_depth1 != function_depth2:
        # This indicates the contexts are from different call paths
        # Use the minimum depth for safety
        min_depth = min(function_depth1, function_depth2)
        if hasattr(merged, 'set_call_depth'):
            merged.set_call_depth(min_depth)
    
    # Merge function returns information
    returns1 = ctx1.get("function_returns", {})
    returns2 = ctx2.get("function_returns", {})
    merged_returns = {**returns1, **returns2}  # Combine both sets of returns
    merged.set("function_returns", merged_returns)
    
    # Instruction traces can't be meaningfully merged, so we'll pick the longer one
    # as it might contain more information
    trace1 = ctx1.get("instruction_trace", [])
    trace2 = ctx2.get("instruction_trace", [])
    merged.set("instruction_trace", trace1 if len(trace1) >= len(trace2) else trace2)
    
    return merged
