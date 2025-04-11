# tests/test_symbolic.py
import pytest
from ..core.symbolic import (
    SymbolicExecutor,
    SymbolicValue,
    SymbolicType,
    SymbolicEVMState,
    Z3SolverContext,
    PathConstraint,
)
import z3


# Basic tests for SymbolicValue creation and Z3 conversion
def test_symbolic_value_concrete():
    ctx = Z3SolverContext()
    val = SymbolicValue(type=SymbolicType.CONCRETE, concrete_value=123, size=256)
    z3_val = val.to_z3(ctx)
    assert isinstance(z3_val, z3.BitVecNumRef)
    assert z3_val.as_long() == 123
    assert z3_val.size() == 256
    assert val.is_concrete()
    assert not val.is_symbolic()


def test_symbolic_value_symbolic():
    ctx = Z3SolverContext()
    val = SymbolicValue(type=SymbolicType.SYMBOLIC, name="my_var", size=64)
    z3_val = val.to_z3(ctx)
    assert isinstance(z3_val, z3.BitVecRef)
    assert str(z3_val) == "my_var"  # Z3 variable name
    assert z3_val.size() == 64
    assert not val.is_concrete()
    assert val.is_symbolic()


def test_symbolic_value_expression():
    ctx = Z3SolverContext()
    a = SymbolicValue(type=SymbolicType.CONCRETE, concrete_value=5, size=8)
    b = SymbolicValue(type=SymbolicType.SYMBOLIC, name="b_var", size=8)
    expr_val = a + b  # Uses overloaded operator
    assert expr_val.type == SymbolicType.EXPRESSION
    assert expr_val.size == 8
    assert not expr_val.is_concrete()
    assert expr_val.is_symbolic()

    z3_expr = expr_val.to_z3(ctx)
    assert isinstance(z3_expr, z3.BitVecRef)  # Z3 expressions are refs
    # Check the structure (optional, can be brittle)
    # assert z3_expr.decl().name() == 'bvadd'


# Tests for Z3SolverContext
def test_z3_context_get_create_var():
    ctx = Z3SolverContext()
    var1 = ctx.get_or_create_var("test_var", 256)
    var2 = ctx.get_or_create_var("test_var", 256)
    var3 = ctx.get_or_create_var("other_var", 64)
    assert var1 is var2  # Should return the same Z3 object
    assert str(var1) == "test_var"
    assert var1.size() == 256
    assert str(var3) == "other_var"
    assert var3.size() == 64


# Tests for PathConstraint
def test_path_constraint_true():
    ctx = Z3SolverContext()
    # Condition: symbolic_var == 10 (results in size 1 SymbolicValue)
    sym_var = SymbolicValue(type=SymbolicType.SYMBOLIC, name="cond_var", size=8)
    cond_val = sym_var == 10  # Symbolic comparison
    constraint = PathConstraint(condition=cond_val, taken=True)
    z3_cond = constraint.to_z3(ctx)

    assert isinstance(z3_cond, z3.BoolRef)
    # Check satisfiability with the condition
    ctx.solver.push()
    ctx.solver.add(z3_cond)
    ctx.solver.add(ctx.get_or_create_var("cond_var", 8) == 10)
    assert ctx.solver.check() == z3.sat
    ctx.solver.pop()

    # Check satisfiability against the condition
    ctx.solver.push()
    ctx.solver.add(z3_cond)
    ctx.solver.add(ctx.get_or_create_var("cond_var", 8) == 5)  # Contradiction
    assert ctx.solver.check() == z3.unsat
    ctx.solver.pop()


def test_path_constraint_false():
    ctx = Z3SolverContext()
    sym_var = SymbolicValue(type=SymbolicType.SYMBOLIC, name="cond_var2", size=8)
    cond_val = sym_var > 100  # Symbolic comparison
    constraint = PathConstraint(condition=cond_val, taken=False)  # Not taken
    z3_cond = constraint.to_z3(ctx)  # Should be z3.Not(sym_var > 100)

    assert isinstance(z3_cond, z3.BoolRef)

    # Check satisfiability with the negated condition (e.g., var <= 100)
    ctx.solver.push()
    ctx.solver.add(z3_cond)
    ctx.solver.add(ctx.get_or_create_var("cond_var2", 8) == 50)
    assert ctx.solver.check() == z3.sat
    ctx.solver.pop()

    # Check satisfiability against the negated condition (e.g., var > 100)
    ctx.solver.push()
    ctx.solver.add(z3_cond)
    ctx.solver.add(ctx.get_or_create_var("cond_var2", 8) == 150)  # Contradiction
    assert ctx.solver.check() == z3.unsat
    ctx.solver.pop()


# Tests for SymbolicEVMState
def test_symbolic_state_clone():
    state = SymbolicEVMState(current_address="0x123")
    state.stack.append(SymbolicValue(type=SymbolicType.CONCRETE, concrete_value=1))
    state.storage["0x123"] = {0: SymbolicValue(type=SymbolicType.SYMBOLIC, name="s_0")}
    state.path_constraints.append(
        PathConstraint(
            SymbolicValue(type=SymbolicType.CONCRETE, concrete_value=1, size=1)
        )
    )

    clone = state.clone()

    # Check independence
    clone.stack.append(SymbolicValue(type=SymbolicType.CONCRETE, concrete_value=2))
    clone.storage["0x123"][1] = SymbolicValue(
        type=SymbolicType.CONCRETE, concrete_value=99
    )
    clone.path_constraints.append(
        PathConstraint(
            SymbolicValue(type=SymbolicType.CONCRETE, concrete_value=0, size=1)
        )
    )
    clone.current_address = "0x456"

    assert len(state.stack) == 1
    assert len(clone.stack) == 2
    assert 1 not in state.storage["0x123"]
    assert clone.storage["0x123"][1].concrete_value == 99
    assert len(state.path_constraints) == 1
    assert len(clone.path_constraints) == 2
    assert state.current_address == "0x123"
    assert clone.current_address == "0x456"


# Tests for SymbolicExecutor (more involved, need mock bytecode/handlers)
# Placeholder for basic initialization test
def test_symbolic_executor_init():
    executor = SymbolicExecutor()
    assert executor.solver_context is not None
    assert isinstance(executor.solver_context, Z3SolverContext)


# TODO: Add tests for execute_symbolic with simple bytecode examples
# These would require implementing basic opcode handlers (STOP, PUSH, ADD, JUMPI)
# and mocking transaction/block context.

def test_execute_symbolic_simple_add():
    executor = SymbolicExecutor()
    # Bytecode: PUSH1 0x05, PUSH1 0x0a, ADD, STOP
    bytecode = bytes.fromhex("6005600a0100")
    contract_address = "0x1111111111111111111111111111111111111111"
    sender_address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    # Mock transaction and block context
    mock_tx = {
        "from": sender_address,
        "to": contract_address,
        "gas": 200000,
        "value": 0,
        "input": "0x",
    }
    mock_block = {"number": 1, "timestamp": 1678886400, "difficulty": 0}

    # Execute symbolically
    paths = executor.execute_symbolic(
        mock_tx, mock_block, bytecode, contract_address, max_paths=1, max_depth=10
    )

    # Assertions
    assert len(paths) == 1, "Should find exactly one execution path"
    final_state, reason = paths[0]

    assert reason == "STOP", "Path should terminate with STOP"
    assert isinstance(
        final_state, SymbolicEVMState
    ), "Final state should be SymbolicEVMState"
    assert len(final_state.stack) == 1, "Final stack should have one item"

    result_val = final_state.stack[0]
    assert isinstance(result_val, SymbolicValue), "Stack item should be SymbolicValue"
    assert result_val.is_concrete(), "Result should be concrete"
    assert (
        result_val.get_concrete_value() == 15
    ), "Result of 5 + 10 should be 15"
