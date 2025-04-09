from z3 import Solver, Bool, And, Or, Not, Implies, sat
from decompiler.utils.z3_utils import setup_jump_constraints

def classify_jumps(jumps, blocks, stack_analysis):
    """
    Classify each jump instruction according to the rules:
    
    1. JUMPI instructions are intra-procedural jumps
    2. JUMP with locally resolved unique target is intra-procedural
    3. JUMP with locally resolved escaping destination is a private call
    4. JUMP with non-locally resolved target is a private return or continuation
    """
    solver, jump_vars = setup_jump_constraints(jumps, blocks, stack_analysis)
    
    # Solve constraints
    if solver.check() == sat:
        model = solver.model()
        
        # Extract classifications
        classifications = {}
        for jump_id, props in jump_vars.items():
            if model.evaluate(props['is_intra_proc']):
                classifications[jump_id] = 'intra-procedural'
            elif model.evaluate(props['is_private_call']):
                classifications[jump_id] = 'private-call'
            elif model.evaluate(props['is_private_return']):
                classifications[jump_id] = 'private-return'
        
        return classifications
    else:
        raise Exception("Constraints unsatisfiable")
