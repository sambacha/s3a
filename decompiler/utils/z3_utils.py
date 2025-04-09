from z3 import *


def setup_jump_constraints(jumps, blocks, stack_analysis):
    """
    Set up Z3 constraints for jump classification.
    """
    solver = Solver()

    # Create Boolean variables for each property of each jump
    jump_vars = {}
    for jump_id, jump in jumps.items():
        jump_vars[jump_id] = {
            "locally_resolved": Bool(f"locally_resolved_{jump_id}"),
            "unique_target": Bool(f"unique_target_{jump_id}"),
            "escaping_dest": Bool(f"escaping_dest_{jump_id}"),
            "is_intra_proc": Bool(f"is_intra_proc_{jump_id}"),
            "is_private_call": Bool(f"is_private_call_{jump_id}"),
            "is_private_return": Bool(f"is_private_return_{jump_id}"),
        }

    # Add constraints based on the classification rules
    for jump_id, jump in jumps.items():
        vars = jump_vars[jump_id]

        # Rule 1: JUMPI instructions are intra-procedural jumps
        if jump.opcode == "JUMPI":
            solver.add(vars["is_intra_proc"])
            solver.add(Not(vars["is_private_call"]))
            solver.add(Not(vars["is_private_return"]))

        # Rule 1: JUMPI instructions are intra-procedural jumps
        if jump.opcode == "JUMPI":
            solver.add(vars["is_intra_proc"])
            solver.add(Not(vars["is_private_call"]))
            solver.add(Not(vars["is_private_return"]))
        else:
            # JUMP with locally resolved unique target is intra-procedural
            solver.add(
                Implies(
                    And(vars["locally_resolved"], vars["unique_target"]),
                    vars["is_intra_proc"],
                )
            )

            # JUMP with locally resolved escaping destination is a private call
            solver.add(
                Implies(
                    And(vars["locally_resolved"], vars["escaping_dest"]),
                    vars["is_private_call"],
                )
            )

            # JUMP with non-locally resolved target is a private return
            solver.add(
                Implies(Not(vars["locally_resolved"]), vars["is_private_return"])
            )

        # Each jump must have exactly one classification
        solver.add(
            Or(
                And(
                    vars["is_intra_proc"],
                    Not(vars["is_private_call"]),
                    Not(vars["is_private_return"]),
                ),
                And(
                    Not(vars["is_intra_proc"]),
                    vars["is_private_call"],
                    Not(vars["is_private_return"]),
                ),
                And(
                    Not(vars["is_intra_proc"]),
                    Not(vars["is_private_call"]),
                    vars["is_private_return"],
                ),
            )
        )

    return solver, jump_vars
