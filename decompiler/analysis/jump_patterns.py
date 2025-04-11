"""
Module for identifying common EVM jump patterns to aid in jump classification.
This helps determine the semantic purpose of jumps (function calls, returns, etc.)
"""

from typing import Dict, Any, Optional, List, Set, Tuple
from ..core.basic_block import BasicBlock
from ..core.instruction import Instruction

def identify_jump_patterns(jumps: Dict[int, Instruction], blocks: Dict[int, BasicBlock]) -> Dict[int, Dict[str, Any]]:
    """
    Identify common patterns in jumps to help classification.
    
    Args:
        jumps: Dictionary of jump instructions keyed by offset
        blocks: Dictionary of basic blocks keyed by start offset
        
    Returns:
        Dictionary mapping jump IDs to pattern information:
        {
            jump_offset: {
                "pattern": pattern_name,
                "confidence": confidence_score (0.0-1.0),
                "metadata": additional_info
            }
        }
    """
    patterns = {}
    
    # Find the block containing each jump
    jump_to_block = {}
    for jump_id, jump_instr in jumps.items():
        containing_block = None
        for block_start, block in blocks.items():
            instr_offsets = [instr.offset for instr in block.instructions]
            if jump_id in instr_offsets:
                 containing_block = block
                 jump_to_block[jump_id] = block
                 break
    
    # Process each jump
    for jump_id, jump_instr in jumps.items():
        containing_block = jump_to_block.get(jump_id)
        if not containing_block:
            continue
            
        # Get information about the jump
        is_conditional = jump_instr.opcode == "JUMPI"
        instructions = containing_block.instructions
        jump_idx = next((i for i, instr in enumerate(instructions) if instr.offset == jump_id), -1)
        
        # Skip if we can't find the jump in the block (should not happen)
        if jump_idx == -1:
            continue
            
        # Pattern 1: Direct jump (PUSH followed by JUMP)
        # These are typically intra-procedural jumps for control flow
        if jump_idx > 0 and instructions[jump_idx-1].opcode.startswith("PUSH"):
            patterns[jump_id] = {
                "pattern": "direct_jump",
                "confidence": 0.9,
                "metadata": {
                    "target": instructions[jump_idx-1].operands[0] if instructions[jump_idx-1].operands else None
                }
            }
            
        # Pattern 2: Function call (stack manipulation followed by JUMP)
        # Look for sequence: [stack setup] -> [address push] -> JUMP
        # Typical call pattern prepares arguments then jumps to function
        elif jump_idx > 2 and not is_conditional:
            # Check for argument loading pattern before jump
            arg_setup = False
            for i in range(jump_idx-3, jump_idx-1):
                if i >= 0 and (instructions[i].opcode.startswith("PUSH") or
                               instructions[i].opcode.startswith("DUP") or
                               instructions[i].opcode.startswith("SWAP")):
                    arg_setup = True
            
            if arg_setup and instructions[jump_idx-1].opcode.startswith("PUSH"):
                patterns[jump_id] = {
                    "pattern": "function_call",
                    "confidence": 0.8,
                    "metadata": {
                        "target": instructions[jump_idx-1].operands[0] if instructions[jump_idx-1].operands else None
                    }
                }
                
        # Pattern 3: Function return
        # Returns often load a return address from stack, then jump
        elif jump_idx > 0 and not is_conditional and not instructions[jump_idx-1].opcode.startswith("PUSH"):
            if any(instr.opcode in ("SWAP1", "SWAP2", "SWAP3", "SWAP4") for instr in instructions[max(0, jump_idx-5):jump_idx]):
                patterns[jump_id] = {
                    "pattern": "function_return",
                    "confidence": 0.7,
                    "metadata": {
                        "has_swap": True
                    }
                }
                
        # Pattern 4: Conditional branch (JUMPI)
        # Typically part of if/else or loop constructs
        elif is_conditional:
            patterns[jump_id] = {
                "pattern": "conditional_branch",
                "confidence": 0.9,
                "metadata": {
                    "target": instructions[jump_idx-2].operands[0] if jump_idx >= 2 and 
                                instructions[jump_idx-2].opcode.startswith("PUSH") and
                                instructions[jump_idx-2].operands else None,
                    "condition_from_push": instructions[jump_idx-1].opcode.startswith("PUSH") if jump_idx >= 1 else False
                }
            }
                
        # Pattern 5: Fallback (if no pattern matches)
        if jump_id not in patterns:
            patterns[jump_id] = {
                "pattern": "unknown",
                "confidence": 0.1,
                "metadata": {
                    "is_conditional": is_conditional
                }
            }

    return patterns

def find_function_entry_patterns(blocks: Dict[int, BasicBlock]) -> Set[int]:
    """
    Identify likely function entry points based on common patterns.
    
    Args:
        blocks: Dictionary of basic blocks
        
    Returns:
        Set of block start offsets that appear to be function entries
    """
    function_entries = set()
    
    for start_offset, block in blocks.items():
        # Pattern: Block starts with JUMPDEST and has stack setup code
        if (block.instructions and 
            block.instructions[0].opcode == "JUMPDEST"):
            
            # Check for argument manipulation in first few instructions
            arg_manipulation = False
            for i in range(1, min(5, len(block.instructions))):
                instr = block.instructions[i]
                if (instr.opcode.startswith("DUP") or 
                    instr.opcode.startswith("SWAP") or
                    instr.opcode == "POP"):
                    arg_manipulation = True
                    break
                    
            if arg_manipulation:
                function_entries.add(start_offset)
                
            # Pattern: Block has many predecessors (called from multiple places)
            if len(block.predecessors) > 1:
                function_entries.add(start_offset)
                
    return function_entries

def analyze_block_relationships(blocks: Dict[int, BasicBlock]) -> Dict[str, Any]:
    """
    Analyze relationships between blocks to identify potential functions.
    
    Args:
        blocks: Dictionary of basic blocks
        
    Returns:
        Dictionary with analysis results
    """
    # Identify potential function entries
    function_entries = find_function_entry_patterns(blocks)
    
    # Find blocks that appear to be shared across functions
    # (blocks with multiple predecessors that aren't function entries)
    shared_blocks = set()
    for start_offset, block in blocks.items():
        if start_offset not in function_entries and len(block.predecessors) > 1:
            shared_blocks.add(start_offset)
            
    # Find potential exit blocks (blocks with RETURN, REVERT, etc.)
    exit_blocks = set()
    for start_offset, block in blocks.items():
        if block.instructions:
            last_instr = block.instructions[-1]
            if last_instr.opcode in ("RETURN", "REVERT", "STOP", "SELFDESTRUCT"):
                exit_blocks.add(start_offset)
                
    return {
        "function_entries": function_entries,
        "shared_blocks": shared_blocks,
        "exit_blocks": exit_blocks
    }
