from decompiler.core.function import Function
from decompiler.analysis.jump_patterns import analyze_block_relationships


def find_return_instructions(jumps, jump_classifications):
    """
    Identify potential return instructions.
    Returns JUMP instructions classified as 'private-return'.
    """
    returns = []
    for jump_offset, jump_instr in jumps.items():
        if jump_classifications.get(jump_offset) == "private-return":
            returns.append(jump_instr)
    return returns


def find_call_sites(jumps, jump_classifications, blocks):
    """
    Identify call sites (private-call JUMPs).
    
    Args:
        jumps: Dictionary of jump instructions
        jump_classifications: Dictionary mapping jump offsets to classifications
        blocks: Dictionary of basic blocks
        
    Returns:
        List of tuples (jump_instr, target_offset)
    """
    call_sites = []
    
    for jump_offset, jump_instr in jumps.items():
        if jump_classifications.get(jump_offset) == "private-call":
            # Find the target of the call if available
            target = None
            # Check if the instruction before the jump is a PUSH with target
            containing_block = None
            for block in blocks.values():
                if any(instr.offset == jump_offset for instr in block.instructions):
                    containing_block = block
                    break
                    
            if containing_block:
                instructions = containing_block.instructions
                jump_idx = next((i for i, instr in enumerate(instructions) if instr.offset == jump_offset), -1)
                
                if jump_idx > 0 and instructions[jump_idx-1].opcode.startswith("PUSH"):
                    target = instructions[jump_idx-1].operands[0] if instructions[jump_idx-1].operands else None
            
            call_sites.append((jump_instr, target))
    
    return call_sites


def match_call_to_returns(call_sites, returns, blocks):
    """
    Match call sites to their potential return instructions.
    This uses a more sophisticated approach based on CFG analysis.
    
    Args:
        call_sites: List of call site tuples (jump_instr, target_offset)
        returns: List of return instructions
        blocks: Dictionary of basic blocks
        
    Returns:
        List of call-return pairs {call: call_instr, target: target_offset, returns: [return_instrs]}
    """
    call_return_pairs = []
    
    # Group return instructions by the block they're in
    returns_by_block = {}
    for ret_instr in returns:
        for block in blocks.values():
            if any(instr.offset == ret_instr.offset for instr in block.instructions):
                if block.start_offset not in returns_by_block:
                    returns_by_block[block.start_offset] = []
                returns_by_block[block.start_offset].append(ret_instr)
                break
    
    # Match each call to the returns in reachable blocks
    for call_instr, target_offset in call_sites:
        if target_offset and target_offset in blocks:
            # Simple approach: associate returns in the function with this call
            function_returns = []
            
            # Start with returns in the target block
            if target_offset in returns_by_block:
                function_returns.extend(returns_by_block[target_offset])
            
            # FIXME: More sophisticated approach would traverse the CFG from the target
            # to find all reachable return instructions
            
            call_return_pairs.append({
                "call": call_instr,
                "target": target_offset,
                "returns": function_returns
            })
    
    return call_return_pairs


def create_function_objects(call_return_pairs, blocks, jumps, jump_classifications):
    """
    Create Function objects based on call/return pairs.
    
    Args:
        call_return_pairs: List of call-return pairs
        blocks: Dictionary of basic blocks
        jumps: Dictionary of jump instructions
        jump_classifications: Dictionary mapping jump offsets to classifications
        
    Returns:
        Dictionary mapping function entry points to Function objects
    """
    functions = {}
    
    # Also use pattern analysis to identify potential function entry points
    block_relationships = analyze_block_relationships(blocks)
    function_entries = block_relationships["function_entries"]
    
    # 1. First create functions based on direct pattern analysis
    for entry_offset in function_entries:
        if entry_offset in blocks and entry_offset not in functions:
            functions[entry_offset] = Function(entry_block=blocks[entry_offset])
    
    # 2. Then add functions based on call/return analysis
    for pair in call_return_pairs:
        target_offset = pair["target"]
        if target_offset in blocks and target_offset not in functions:
            functions[target_offset] = Function(entry_block=blocks[target_offset])
            
            # Add return instructions if available
            if "returns" in pair and pair["returns"]:
                exit_blocks = []
                for ret_instr in pair["returns"]:
                    for block in blocks.values():
                        if any(instr.offset == ret_instr.offset for instr in block.instructions):
                            exit_blocks.append(block)
                            break
                
                functions[target_offset].exit_blocks = exit_blocks
    
    # Identify function blocks through reachability analysis
    for func_offset, function in functions.items():
        function.blocks = identify_function_blocks(function.entry_block, blocks, jump_classifications)
    
    return functions


def identify_function_blocks(entry_block, blocks, jump_classifications):
    """
    Identify all blocks belonging to a function through reachability.
    
    Args:
        entry_block: Entry basic block of the function
        blocks: Dictionary of all basic blocks
        jump_classifications: Dictionary mapping jump offsets to classifications
        
    Returns:
        Set of blocks belonging to the function
    """
    function_blocks = set()
    worklist = [entry_block]
    visited = set()
    
    while worklist:
        block = worklist.pop()
        if block in visited:
            continue
            
        visited.add(block)
        function_blocks.add(block)
        
        # Add successors that don't cross function boundaries
        for successor in block.successors:
            # Check if this edge crosses a function boundary
            is_call_edge = False
            for instr in block.instructions:
                if instr.offset in jump_classifications and jump_classifications[instr.offset] == "private-call":
                    # This is a call edge - don't follow
                    is_call_edge = True
                    break
            
            if not is_call_edge:
                worklist.append(successor)
    
    return function_blocks


def infer_function_boundaries(jumps, blocks, jump_classifications, stack_analysis):
    """
    Enhanced approach to function boundary identification.
    
    Four-step process:
    1. Find likely return instructions
    2. Find call sites with target blocks
    3. Match calls to returns based on reachability
    4. Create Function objects
    
    Args:
        jumps: Dictionary of jump instructions
        blocks: Dictionary of basic blocks
        jump_classifications: Dictionary mapping jump offsets to classifications
        stack_analysis: Stack analysis results (not used in this implementation)
        
    Returns:
        Dictionary mapping function entry points to Function objects
    """
    # 1. Find return instructions
    returns = find_return_instructions(jumps, jump_classifications)
    
    # 2. Find call sites
    call_sites = find_call_sites(jumps, jump_classifications, blocks)
    
    # 3. Match calls to returns
    call_return_pairs = match_call_to_returns(call_sites, returns, blocks)
    
    # 4. Create Function objects
    functions = create_function_objects(call_return_pairs, blocks, jumps, jump_classifications)
    
    return functions
