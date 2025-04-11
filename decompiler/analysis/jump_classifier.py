from z3 import Solver, Bool, And, Or, Not, Implies, sat
from decompiler.utils.z3_utils import setup_jump_constraints
from decompiler.analysis.jump_patterns import identify_jump_patterns


def classify_jumps(jumps, blocks, stack_analysis):
    """
    Enhanced jump classification using both Z3 constraints and pattern analysis.
    
    This combines two approaches:
    1. Constraint-based analysis using Z3
    2. Pattern recognition of common EVM jump patterns
    
    The final classification weighs both approaches, giving preference to
    constraint-based analysis but using patterns where constraints are inconclusive.
    
    Args:
        jumps: Dictionary of jump instructions keyed by offset
        blocks: Dictionary of basic blocks
        stack_analysis: Results from symbolic analysis of jumps
        
    Returns:
        Dictionary mapping jump offsets to classifications:
        {offset: classification_string}
        
    Classification strings:
    - "intra-procedural": For control flow within a function
    - "private-call": For function calls
    - "private-return": For returning from functions
    - "unknown": For unclassified jumps
    """
    # First, analyze jump patterns
    patterns = identify_jump_patterns(jumps, blocks)
    
    # Setup and solve Z3 constraints
    try:
        solver, jump_vars = setup_jump_constraints(jumps, blocks, stack_analysis)
        
        # Attempt to solve constraints
        if solver.check() == sat:
            model = solver.model()
            
            # Extract classifications from Z3 model
            classifications = {}
            for jump_id, props in jump_vars.items():
                if model.evaluate(props["is_intra_proc"]):
                    classifications[jump_id] = "intra-procedural"
                elif model.evaluate(props["is_private_call"]):
                    classifications[jump_id] = "private-call"
                elif model.evaluate(props["is_private_return"]):
                    classifications[jump_id] = "private-return"
                else:
                    # If Z3 couldn't classify, use pattern-based classification
                    classifications[jump_id] = classify_by_pattern(jump_id, patterns)
            
            return classifications
        else:
            # Fallback to pattern-based classification if constraints unsatisfiable
            print("Z3 constraints unsatisfiable, falling back to pattern analysis")
            return {jump_id: classify_by_pattern(jump_id, patterns) for jump_id in jumps}
    
    except Exception as e:
        # Handle any errors in Z3 constraint setup or solving
        print(f"Error in Z3 constraint solving: {e}")
        # Fallback to pattern analysis
        return {jump_id: classify_by_pattern(jump_id, patterns) for jump_id in jumps}


def classify_by_pattern(jump_id, patterns):
    """
    Classify a jump based on pattern analysis results.
    
    Args:
        jump_id: Offset of the jump instruction
        patterns: Results from identify_jump_patterns
        
    Returns:
        Classification string
    """
    if jump_id not in patterns:
        return "unknown"
    
    pattern_info = patterns[jump_id]
    pattern_type = pattern_info["pattern"]
    
    # Map pattern types to jump classifications
    if pattern_type == "direct_jump" or pattern_type == "conditional_branch":
        return "intra-procedural"
    elif pattern_type == "function_call":
        return "private-call"
    elif pattern_type == "function_return":
        return "private-return"
    else:
        return "unknown"
