import sys

# Assuming analyze_stack_locally has populated block.stack_effect = (pushes, pops)
# and block.stack_height_in (required input height for the block)

def infer_function_arguments(function, all_blocks):
    """
    Perform path-sensitive analysis within a function's blocks to estimate arguments and returns.

    Args:
        function: The Function object (assumed to have entry_block and blocks attributes).
        all_blocks: Dictionary mapping start_offset to all BasicBlock objects.

    Returns:
        Tuple[int, int]: Estimated number of arguments (max stack consumption relative to entry)
                         and return values (stack height delta at exit).
    """
    if not function or not function.entry_block or not function.blocks:
        print("[Warning] Invalid function object passed to infer_function_arguments", file=sys.stderr)
        return 0, 0 # Cannot analyze without entry/blocks

    entry_block = function.entry_block
    function_block_offsets = {b.start_offset for b in function.blocks}

    max_pops_relative = 0 # Max stack elements consumed relative to entry height
    exit_deltas = set()   # Stack height delta relative to entry height at exit points

    # Worklist for DFS: (block_offset, entry_stack_height_relative)
    worklist = [(entry_block.start_offset, 0)]
    visited_states = {} # Track visited (block_offset, entry_stack_height_relative) to handle loops

    while worklist:
        current_offset, current_height_relative = worklist.pop()

        # Prevent infinite loops and redundant work
        state_key = (current_offset, current_height_relative)
        if state_key in visited_states and visited_states[state_key] > 10: # Limit visits to break deep cycles
             continue
        visited_states[state_key] = visited_states.get(state_key, 0) + 1

        if current_offset not in all_blocks:
            continue # Should not happen if CFG is consistent

        block = all_blocks[current_offset]

        # Calculate min height within the block relative to block entry
        # Requires stack_height_in from analyze_stack_locally
        min_height_in_block_relative = -(block.stack_height_in if block.stack_height_in is not None else 0)

        # Max pops relative to function entry = current height - min height reached in block
        current_max_pops = current_height_relative - min_height_in_block_relative
        max_pops_relative = max(max_pops_relative, current_max_pops)

        # Calculate exit height relative to block entry
        pushes, pops = block.stack_effect if block.stack_effect else (0, 0)
        exit_height_block_relative = pushes - pops

        # Calculate exit height relative to function entry
        exit_height_relative = current_height_relative + exit_height_block_relative

        is_exit_block = not block.successors or \
                        any(succ.start_offset not in function_block_offsets for succ in block.successors) or \
                        (block.instructions and block.instructions[-1].opcode in ('RETURN', 'REVERT', 'STOP', 'SELFDESTRUCT'))

        if is_exit_block:
            exit_deltas.add(exit_height_relative)
        else:
            for successor_block in block.successors:
                # Only continue within the function's blocks
                if successor_block.start_offset in function_block_offsets:
                    # Add successor state to worklist
                    if (successor_block.start_offset, exit_height_relative) not in visited_states or visited_states[(successor_block.start_offset, exit_height_relative)] <= 10:
                         worklist.append((successor_block.start_offset, exit_height_relative))


    # Estimate arguments based on max relative pops
    num_args = max_pops_relative

    # Estimate return values based on exit deltas
    # If multiple exit paths have different stack heights, it's complex.
    # Simplification: if all exit deltas are the same, use that. Otherwise, maybe 0 or -1?
    num_returns = 0
    if len(exit_deltas) == 1:
        num_returns = list(exit_deltas)[0]
    elif len(exit_deltas) > 1:
        # Inconsistent exit stack heights, difficult to determine statically
        # print(f"[Warning] Function at {function.entry_block.start_offset} has inconsistent exit stack heights: {exit_deltas}", file=sys.stderr)
        # Could try to find a common minimum, or default to 0 or 1 if positive?
        # For now, let's take the minimum positive delta if available, else 0
        positive_deltas = [d for d in exit_deltas if d >= 0]
        num_returns = min(positive_deltas) if positive_deltas else 0


    # Ensure non-negative results
    num_args = max(0, num_args)
    num_returns = max(0, num_returns)

    # Update function object (optional, depends on design)
    function.args = num_args
    function.returns = num_returns

    return num_args, num_returns
