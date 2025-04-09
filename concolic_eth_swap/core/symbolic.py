# core/symbolic.py
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Set, Tuple, Callable, Any
from enum import Enum
import z3
import structlog
import evmole  # Import evmole
from evmole.evm import Instruction  # Import Instruction type

logger = structlog.get_logger()


class SymbolicType(Enum):
    CONCRETE = 1
    SYMBOLIC = 2
    EXPRESSION = 3


# Forward declaration for type hint
class Z3SolverContext:
    def __init__(self):
        self.solver = z3.Solver()
        self.variables: Dict[str, z3.BitVecRef] = {}  # name -> z3 variable

    def get_or_create_var(self, name: str, size: int) -> z3.BitVecRef:
        if name not in self.variables:
            self.variables[name] = z3.BitVec(name, size)
            logger.debug(f"Created symbolic variable: {name}[{size}]")
        var = self.variables[name]
        # Z3 variables are typed by size, ensure consistency
        if var.size() != size:
            # This case should ideally not happen if names are unique per size,
            # or names incorporate size. Recreating might hide bugs.
            logger.error(
                f"Variable '{name}' requested with size {size}, but exists with size {var.size()}! Returning existing.",
                existing_var=var,
            )
            # raise ValueError(f"Variable '{name}' size mismatch: requested {size}, exists {var.size()}")
        return var

    def check_satisfiability(self, constraints: List["PathConstraint"]) -> bool:
        """Check if a set of path constraints is satisfiable using Z3"""
        self.solver.push()
        try:
            for constraint in constraints:
                z3_constraint = constraint.to_z3(self)
                self.solver.add(z3_constraint)

            result = self.solver.check()
            logger.debug(
                "Satisfiability check", constraints=len(constraints), result=str(result)
            )
            return result == z3.sat
        except Exception as e:
            logger.exception("Error during satisfiability check", error=str(e))
            return False  # Treat errors as unsatisfiable for safety
        finally:
            self.solver.pop()

    def get_model_value(self, symbolic_value: "SymbolicValue") -> Optional[int]:
        """Get a concrete value from the current model if satisfiable"""
        if self.solver.check() == z3.sat:
            model = self.solver.model()
            try:
                z3_expr = symbolic_value.to_z3(self)
                eval_result = model.eval(z3_expr, model_completion=True)
                if isinstance(eval_result, z3.BitVecNumRef):
                    return eval_result.as_long()
                elif isinstance(eval_result, z3.BoolRef):
                    # Convert Z3 boolean to int (0 or 1)
                    return 1 if z3.is_true(eval_result) else 0
                else:
                    logger.warning(
                        "Model evaluation returned unexpected type",
                        type=type(eval_result),
                        value=eval_result,
                    )
                    return None  # Or raise error?
            except Exception as e:
                logger.exception("Error evaluating model value", error=str(e))
                return None
        else:
            logger.debug("Cannot get model value, constraints are unsatisfiable")
            return None


@dataclass
class SymbolicValue:
    type: SymbolicType
    name: Optional[str] = None
    concrete_value: Optional[int] = None
    expression: Optional[object] = None  # Should be z3.ExprRef or similar
    size: int = 256  # Default size in bits

    def to_z3(self, solver_context: Z3SolverContext) -> z3.ExprRef:
        if self.type == SymbolicType.CONCRETE:
            if self.concrete_value is None:
                raise ValueError("Concrete SymbolicValue must have a concrete_value")
            return z3.BitVecVal(self.concrete_value, self.size)
        elif self.type == SymbolicType.SYMBOLIC:
            if self.name is None:
                raise ValueError("Symbolic SymbolicValue must have a name")
            return solver_context.get_or_create_var(self.name, self.size)
        elif self.type == SymbolicType.EXPRESSION:
            if self.expression is None:
                raise ValueError("Expression SymbolicValue must have an expression")
            if not isinstance(self.expression, z3.ExprRef):
                logger.warning(
                    f"SymbolicValue expression is not a Z3 ExprRef: {type(self.expression)}"
                )
            return self.expression  # type: ignore
        else:
            raise TypeError(f"Unknown SymbolicType: {self.type}")

    # --- Arithmetic Operations ---
    def __add__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":
        return symbolic_binary_op(z3.Add, self, other)

    def __sub__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":
        return symbolic_binary_op(z3.Sub, self, other)

    def __mul__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":
        return symbolic_binary_op(z3.Mul, self, other)

    def __truediv__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # SDIV (signed)
        return symbolic_binary_op(
            lambda a, b: a / b, self, other
        )  # Z3 uses signed division by default

    def __floordiv__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # DIV (unsigned)
        return symbolic_binary_op(z3.UDiv, self, other)

    def __mod__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # MOD (unsigned)
        return symbolic_binary_op(z3.URem, self, other)

    # SMOD (signed modulo) needs careful handling if needed, Z3 has SRem

    # --- Bitwise Operations ---
    def __and__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":
        return symbolic_binary_op(lambda a, b: a & b, self, other)

    def __or__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":
        return symbolic_binary_op(lambda a, b: a | b, self, other)

    def __xor__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":
        return symbolic_binary_op(lambda a, b: a ^ b, self, other)

    def __invert__(self) -> "SymbolicValue":  # NOT
        return symbolic_unary_op(lambda a: ~a, self)

    def __lshift__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":  # SHL
        return symbolic_binary_op(z3.BVSHL, self, other)

    def __rshift__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # SHR (logical)
        return symbolic_binary_op(z3.LShR, self, other)

    # SAR (arithmetic right shift) needs z3.BVASHR

    # --- Comparison Operations ---
    # Return SymbolicValue representing the boolean result (size 1)
    def __eq__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":  # type: ignore # EQ
        return symbolic_comparison_op(lambda a, b: a == b, self, other)

    def __ne__(self, other: Union["SymbolicValue", int]) -> "SymbolicValue":  # type: ignore # ISZERO (when compared to 0)
        return symbolic_comparison_op(lambda a, b: a != b, self, other)

    def __lt__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # LT (unsigned)
        return symbolic_comparison_op(z3.ULT, self, other)

    def __le__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # Unsigned Less Than or Equal
        return symbolic_comparison_op(z3.ULE, self, other)

    def __gt__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # GT (unsigned)
        return symbolic_comparison_op(z3.UGT, self, other)

    def __ge__(
        self, other: Union["SymbolicValue", int]
    ) -> "SymbolicValue":  # Unsigned Greater Than or Equal
        return symbolic_comparison_op(z3.UGE, self, other)

    # SLT, SGT (signed comparisons) need specific Z3 functions

    def is_concrete(self) -> bool:
        return self.type == SymbolicType.CONCRETE

    def is_symbolic(self) -> bool:
        return (
            self.type == SymbolicType.SYMBOLIC or self.type == SymbolicType.EXPRESSION
        )

    def get_concrete_value(self) -> Optional[int]:
        if self.is_concrete():
            return self.concrete_value
        return None  # Or try to evaluate expression if possible?


# Global context (problematic for concurrency, refactor if needed)
_DEFAULT_SOLVER_CONTEXT = Z3SolverContext()


# Helper for unary ops
def symbolic_unary_op(
    op_func: Callable[[z3.ExprRef], z3.ExprRef],
    operand: SymbolicValue,
    context: Z3SolverContext = _DEFAULT_SOLVER_CONTEXT,
) -> SymbolicValue:
    operand_expr = operand.to_z3(context)
    result_expr = op_func(operand_expr)
    result_size = result_expr.size()
    return SymbolicValue(
        type=SymbolicType.EXPRESSION, expression=result_expr, size=result_size
    )


# Helper for binary ops
def symbolic_binary_op(
    op_func: Callable[[z3.ExprRef, z3.ExprRef], z3.ExprRef],
    left: SymbolicValue,
    right: Union[SymbolicValue, int],
    context: Z3SolverContext = _DEFAULT_SOLVER_CONTEXT,
) -> SymbolicValue:
    if isinstance(right, int):
        size = left.size
        right_sv = SymbolicValue(
            type=SymbolicType.CONCRETE, concrete_value=right, size=size
        )
    elif isinstance(right, SymbolicValue):
        right_sv = right
        if left.size != right_sv.size:
            logger.warning(
                f"Binary op size mismatch: left={left.size}, right={right_sv.size}. Z3 will handle or error."
            )
    else:
        raise TypeError(f"Unsupported type for binary operation: {type(right)}")

    left_expr = left.to_z3(context)
    right_expr = right_sv.to_z3(context)
    result_expr = op_func(left_expr, right_expr)
    result_size = result_expr.size()
    return SymbolicValue(
        type=SymbolicType.EXPRESSION, expression=result_expr, size=result_size
    )


# Helper for comparison ops (returns size 1 symbolic value)
def symbolic_comparison_op(
    op_func: Callable[[z3.ExprRef, z3.ExprRef], z3.BoolRef],
    left: SymbolicValue,
    right: Union[SymbolicValue, int],
    context: Z3SolverContext = _DEFAULT_SOLVER_CONTEXT,
) -> SymbolicValue:
    if isinstance(right, int):
        size = left.size
        right_sv = SymbolicValue(
            type=SymbolicType.CONCRETE, concrete_value=right, size=size
        )
    elif isinstance(right, SymbolicValue):
        right_sv = right
        if left.size != right_sv.size:
            logger.warning(
                f"Comparison op size mismatch: left={left.size}, right={right_sv.size}. Z3 will handle or error."
            )
    else:
        raise TypeError(f"Unsupported type for comparison operation: {type(right)}")

    left_expr = left.to_z3(context)
    right_expr = right_sv.to_z3(context)
    result_expr = op_func(left_expr, right_expr)  # This is a Z3 BoolRef

    # Convert Z3 BoolRef to a BitVecRef of size 1 (0 or 1)
    result_bv = z3.If(result_expr, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))

    return SymbolicValue(type=SymbolicType.EXPRESSION, expression=result_bv, size=1)


@dataclass
class PathConstraint:
    condition: SymbolicValue  # Should represent a boolean expression (size 1)
    taken: bool = True

    def to_z3(self, solver_context: Z3SolverContext) -> z3.BoolRef:
        cond_expr = self.condition.to_z3(solver_context)
        if isinstance(cond_expr, z3.BitVecRef):
            if cond_expr.size() == 1:
                cond_bool = cond_expr == 1  # Compare BitVec size 1 to 1
            else:
                # JUMPI condition: non-zero is true
                cond_bool = cond_expr != 0
        elif isinstance(cond_expr, z3.BoolRef):
            cond_bool = cond_expr
        else:
            raise TypeError(
                f"Path constraint condition evaluated to unexpected Z3 type: {type(cond_expr)}"
            )

        return cond_bool if self.taken else z3.Not(cond_bool)


@dataclass
class SymbolicEVMState:
    memory: Dict[int, SymbolicValue] = field(
        default_factory=dict
    )  # Address -> SymbolicValue (byte?) - Needs better model (e.g., byte array or Z3 array)
    storage: Dict[str, Dict[int, SymbolicValue]] = field(
        default_factory=dict
    )  # Contract Addr -> Slot -> Value
    registers: Dict[str, SymbolicValue] = field(
        default_factory=dict
    )  # PC, SP, GAS etc.
    stack: List[SymbolicValue] = field(default_factory=list)
    path_constraints: List[PathConstraint] = field(default_factory=list)
    token_balances: Dict[str, Dict[str, SymbolicValue]] = field(
        default_factory=dict
    )  # Token Addr -> User Addr -> Balance
    call_stack: List[str] = field(default_factory=list)  # Frames or contract addresses
    bytecode: bytes = b""
    current_address: str = "0x0"
    # Add return data buffer
    return_data: bytes = b""

    def clone(self) -> "SymbolicEVMState":
        # SymbolicValues are immutable or represent immutable Z3 objects, so shallow copy is fine for values.
        # Need deep copy for mutable collections (dicts, lists).
        cloned_storage = {}
        for addr, store in self.storage.items():
            cloned_storage[addr] = store.copy()

        cloned_token_balances = {}
        for token, balances in self.token_balances.items():
            cloned_token_balances[token] = balances.copy()

        return SymbolicEVMState(
            memory=self.memory.copy(),  # Memory model needs refinement (Z3 Array?)
            storage=cloned_storage,
            registers=self.registers.copy(),
            stack=self.stack[:],
            path_constraints=self.path_constraints[:],
            token_balances=cloned_token_balances,
            call_stack=self.call_stack[:],
            bytecode=self.bytecode,  # Immutable
            current_address=self.current_address,  # Immutable
            return_data=self.return_data,  # Immutable
        )


class SymbolicExecutor:
    def __init__(self):
        self.solver_context = Z3SolverContext()
        self.execution_paths: List[Tuple[SymbolicEVMState, str]] = []
        self.states_to_explore: List[Tuple[SymbolicEVMState, int]] = []

        # Opcode handler dispatch table
        self._opcode_handlers: Dict[
            str, Callable[[Instruction, SymbolicEVMState], Dict[str, Any]]
        ] = {
            # 0s: Stop and Arithmetic Operations
            "STOP": self._handle_stop,
            "ADD": self._handle_add,
            "MUL": self._handle_mul,
            "SUB": self._handle_sub,
            "DIV": self._handle_div,
            "SDIV": self._handle_sdiv,
            "MOD": self._handle_mod,
            "SMOD": self._handle_smod,
            "ADDMOD": self._handle_addmod,
            "MULMOD": self._handle_mulmod,
            "EXP": self._handle_exp,
            "SIGNEXTEND": self._handle_signextend,
            # 10s: Comparison & Bitwise Logic Operations
            "LT": self._handle_lt,
            "GT": self._handle_gt,
            "SLT": self._handle_slt,
            "SGT": self._handle_sgt,
            "EQ": self._handle_eq,
            "ISZERO": self._handle_iszero,
            "AND": self._handle_and,
            "OR": self._handle_or,
            "XOR": self._handle_xor,
            "NOT": self._handle_not,
            "BYTE": self._handle_byte,
            "SHL": self._handle_shl,
            "SHR": self._handle_shr,
            "SAR": self._handle_sar,
            # 20s: SHA3
            "SHA3": self._handle_sha3,
            # 30s: Environmental Information
            "ADDRESS": self._handle_address,
            "BALANCE": self._handle_balance,
            "ORIGIN": self._handle_origin,
            "CALLER": self._handle_caller,
            "CALLVALUE": self._handle_callvalue,
            "CALLDATALOAD": self._handle_calldataload,
            "CALLDATASIZE": self._handle_calldatasize,
            "CALLDATACOPY": self._handle_calldatacopy,
            "CODESIZE": self._handle_codesize,
            "CODECOPY": self._handle_codecopy,
            "GASPRICE": self._handle_gasprice,
            "EXTCODESIZE": self._handle_extcodesize,
            "EXTCODECOPY": self._handle_extcodecopy,
            "RETURNDATASIZE": self._handle_returndatasize,
            "RETURNDATACOPY": self._handle_returndatacopy,
            "EXTCODEHASH": self._handle_extcodehash,
            # 40s: Block Information
            "BLOCKHASH": self._handle_blockhash,
            "COINBASE": self._handle_coinbase,
            "TIMESTAMP": self._handle_timestamp,
            "NUMBER": self._handle_number,
            "DIFFICULTY": self._handle_difficulty,  # PREVRANDAO post-merge
            "GASLIMIT": self._handle_gaslimit,
            "CHAINID": self._handle_chainid,
            "SELFBALANCE": self._handle_selfbalance,
            "BASEFEE": self._handle_basefee,
            # 50s: Stack, Memory, Storage and Flow Operations
            "POP": self._handle_pop,
            "MLOAD": self._handle_mload,
            "MSTORE": self._handle_mstore,
            "MSTORE8": self._handle_mstore8,
            "SLOAD": self._handle_sload,
            "SSTORE": self._handle_sstore,
            "JUMP": self._handle_jump,
            "JUMPI": self._handle_jumpi,
            "PC": self._handle_pc,
            "MSIZE": self._handle_msize,
            "GAS": self._handle_gas,
            "JUMPDEST": self._handle_jumpdest,
            # 60s & 70s: Push Operations
            **{f"PUSH{i}": self._handle_push for i in range(1, 33)},
            # 80s: Duplication Operations
            **{f"DUP{i}": self._handle_dup for i in range(1, 17)},
            # 90s: Exchange Operations
            **{f"SWAP{i}": self._handle_swap for i in range(1, 17)},
            # a0s: Logging Operations
            **{f"LOG{i}": self._handle_log for i in range(0, 5)},
            # f0s: System operations
            "CREATE": self._handle_create,
            "CALL": self._handle_call,
            "CALLCODE": self._handle_callcode,
            "RETURN": self._handle_return,
            "DELEGATECALL": self._handle_delegatecall,
            "CREATE2": self._handle_create2,
            "STATICCALL": self._handle_staticcall,
            "REVERT": self._handle_revert,
            "INVALID": self._handle_invalid,
            "SELFDESTRUCT": self._handle_selfdestruct,
        }

    def create_symbolic_variable(self, name: str, size: int = 256) -> SymbolicValue:
        self.solver_context.get_or_create_var(name, size)
        return SymbolicValue(type=SymbolicType.SYMBOLIC, name=name, size=size)

    def create_concrete_value(self, value: int, size: int = 256) -> SymbolicValue:
        masked_value = value & ((1 << size) - 1)
        return SymbolicValue(
            type=SymbolicType.CONCRETE, concrete_value=masked_value, size=size
        )

    def initialize_state(
        self, tx: Dict, block_context: Dict, contract_code: bytes, contract_address: str
    ) -> SymbolicEVMState:
        state = SymbolicEVMState(
            bytecode=contract_code, current_address=contract_address
        )
        sender = tx.get("from", "0xUNKNOWN_SENDER")
        sender_addr_int = int(sender, 16)
        to_addr = tx.get("to", contract_address)
        to_addr_int = int(to_addr, 16) if to_addr else 0

        state.registers["GAS"] = self.create_concrete_value(tx.get("gas", 0), size=64)
        state.registers["CALLVALUE"] = self.create_concrete_value(tx.get("value", 0))
        state.registers["CALLER"] = self.create_concrete_value(sender_addr_int)
        state.registers["ORIGIN"] = self.create_concrete_value(sender_addr_int)
        state.registers["ADDRESS"] = self.create_concrete_value(to_addr_int)
        calldata_hex = tx.get("input", "0x")[2:]
        state.registers["CALLDATASIZE"] = self.create_concrete_value(
            len(bytes.fromhex(calldata_hex)), size=64
        )
        state.registers["CALLDATA"] = calldata_hex  # Store raw hex string

        state.registers["PC"] = self.create_concrete_value(0, size=64)
        state.registers["SP"] = self.create_concrete_value(
            1024, size=64
        )  # Stack pointer starts high and decreases

        state.registers["NUMBER"] = self.create_concrete_value(
            block_context.get("number", 0), size=64
        )
        state.registers["TIMESTAMP"] = self.create_concrete_value(
            block_context.get("timestamp", 0), size=64
        )
        state.registers["DIFFICULTY"] = self.create_concrete_value(
            block_context.get("difficulty", 0)
        )
        state.registers["GASLIMIT"] = self.create_concrete_value(
            block_context.get("gasLimit", 0), size=64
        )
        state.registers["COINBASE"] = self.create_concrete_value(
            int(block_context.get("miner", "0x0"), 16)
        )
        state.registers["BASEFEE"] = self.create_concrete_value(
            block_context.get("baseFeePerGas", 0)
        )
        # CHAINID, SELFBALANCE need specific handling if opcodes are implemented

        # Simplified token balance init
        eth_addr = "ETH"
        usdc_addr = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        state.token_balances[eth_addr] = {
            sender: self.create_symbolic_variable(f"initial_eth_balance_{sender}")
        }
        state.token_balances[usdc_addr] = {
            sender: self.create_symbolic_variable(f"initial_usdc_balance_{sender}")
        }

        logger.info(
            "Initialized symbolic EVM state", address=contract_address, sender=sender
        )
        return state

    def execute_symbolic(
        self,
        tx: Dict,
        block_context: Dict,
        contract_code: bytes,
        contract_address: str,
        max_paths=100,
        max_depth=1000,
    ):
        """
        Performs symbolic execution of the given contract code within the transaction context.
        Uses evmole to parse instructions and dispatches to opcode handlers.
        """
        initial_state = self.initialize_state(
            tx, block_context, contract_code, contract_address
        )
        self.states_to_explore = [(initial_state, 0)]  # Queue of (state, depth)
        self.execution_paths = []  # List of completed (state, reason)
        path_count = 0
        executed_instructions_total = 0

        # Create evmole instance for disassembly
        try:
            evm_parser = evmole.evm.Evm(bytecode=contract_code)
            instructions = {inst.offset: inst for inst in evm_parser.disassemble()}
        except Exception as e:
            logger.exception("Failed to disassemble bytecode with evmole", error=str(e))
            # Cannot proceed without instructions
            return [(initial_state, f"disassembly_error: {e}")]

        processed_states_count = 0  # Debug counter

        while self.states_to_explore and path_count < max_paths:
            current_state, current_depth = self.states_to_explore.pop(
                0
            )  # FIFO exploration
            processed_states_count += 1

            if current_depth > max_depth:
                logger.warning(
                    "Max execution depth reached, terminating path.",
                    depth=current_depth,
                    address=current_state.current_address,
                )
                self.execution_paths.append((current_state, "max_depth_reached"))
                path_count += 1
                continue

            # --- Get current instruction using PC ---
            pc_symval = current_state.registers.get("PC")
            if pc_symval is None or not pc_symval.is_concrete():
                logger.error(
                    "PC is symbolic or missing, cannot execute.",
                    address=current_state.current_address,
                )
                self.execution_paths.append((current_state, "symbolic_pc"))
                path_count += 1
                continue

            pc = pc_symval.get_concrete_value()
            instruction = instructions.get(pc)

            if instruction is None:
                # Could be jump into data or invalid code
                logger.error(
                    "No instruction found at PC. Invalid JUMP destination?",
                    pc=pc,
                    address=current_state.current_address,
                )
                self.execution_paths.append((current_state, "invalid_pc"))
                path_count += 1
                continue

            logger.debug(
                "Executing instruction",
                pc=pc,
                opcode=instruction.opcode_info.mnemonic,
                depth=current_depth,
                state_id=id(current_state),
            )

            # --- Execute Instruction via Handler ---
            handler = self._opcode_handlers.get(
                instruction.opcode_info.mnemonic, self._handle_unimplemented
            )
            terminated = False
            termination_reason = ""
            next_state_handler: Optional[SymbolicEVMState] = (
                None  # State returned by handler if sequential
            )
            branch_states: List[
                SymbolicEVMState
            ] = []  # Branched states returned by handler (e.g., JUMPI)

            try:
                # Handler modifies the state *in place* or returns branches/termination info
                handler_result = handler(instruction, current_state)

                terminated = handler_result.get("terminated", False)
                termination_reason = handler_result.get("reason", "")
                next_state_handler = handler_result.get(
                    "next_state"
                )  # Usually current_state if modified in place
                branch_states = handler_result.get("branch_states", [])

                # If handler didn't return next_state but didn't branch/terminate, assume it modified in place
                if not terminated and not branch_states and next_state_handler is None:
                    next_state_handler = current_state

            except IndexError:
                logger.error(
                    "Stack underflow during execution.",
                    opcode=instruction.opcode_info.mnemonic,
                    pc=pc,
                    address=current_state.current_address,
                )
                terminated = True
                termination_reason = "stack_underflow"
                # State before error is current_state
            except NotImplementedError as e:
                logger.error(
                    f"Encountered unimplemented opcode: {e}. Terminating path.",
                    pc=pc,
                    address=current_state.current_address,
                )
                terminated = True
                termination_reason = f"unimplemented_{instruction.opcode_info.mnemonic}"
                # State before error is current_state
            except Exception as e:
                logger.exception(
                    "Error during symbolic instruction execution.",
                    opcode=instruction.opcode_info.mnemonic,
                    pc=pc,
                    address=current_state.current_address,
                    error=str(e),
                )
                terminated = True
                termination_reason = f"execution_error: {e}"
                # State before error is current_state

            executed_instructions_total += 1

            # --- Process Execution Result ---
            if terminated:
                logger.info(
                    "Symbolic execution path terminated",
                    reason=termination_reason,
                    address=current_state.current_address,
                    pc=pc,
                )
                self.execution_paths.append(
                    (current_state, termination_reason)
                )  # State *before* termination
                path_count += 1
            else:
                # Handle branching from JUMPI etc.
                if branch_states:
                    logger.debug(
                        f"Branching state ({len(branch_states)} branches)",
                        address=current_state.current_address,
                        pc=pc,
                    )
                    for branch_state in branch_states:
                        # Check depth and satisfiability *before* adding to queue
                        if current_depth + 1 <= max_depth:
                            if self.solver_context.check_satisfiability(
                                branch_state.path_constraints
                            ):
                                self.states_to_explore.append(
                                    (branch_state, current_depth + 1)
                                )
                            else:
                                logger.debug(
                                    "Pruning unsatisfiable branch path",
                                    address=branch_state.current_address,
                                )
                        else:
                            logger.warning(
                                "Max depth reached on branch, terminating.",
                                depth=current_depth + 1,
                                address=branch_state.current_address,
                            )
                            self.execution_paths.append(
                                (branch_state, "max_depth_reached")
                            )
                            path_count += 1
                # Handle sequential execution
                elif next_state_handler:
                    # Update PC for the next instruction (if not handled by JUMP/JUMPI)
                    # evmole instructions have `size` including operands
                    if instruction.opcode_info.mnemonic not in [
                        "JUMP",
                        "JUMPI",
                    ]:  # JUMP/JUMPI handlers set PC
                        next_pc = pc + instruction.size
                        next_state_handler.registers["PC"] = self.create_concrete_value(
                            next_pc, size=64
                        )

                    self.states_to_explore.append(
                        (next_state_handler, current_depth + 1)
                    )
                else:
                    # Should not happen: not terminated, no branches, no next state
                    logger.error(
                        "Execution step resulted in inconsistent state. Terminating path.",
                        address=current_state.current_address,
                        pc=pc,
                    )
                    self.execution_paths.append(
                        (current_state, "internal_error_no_next_state")
                    )
                    path_count += 1

        logger.info(
            "Symbolic execution finished.",
            explored_paths=path_count,
            total_instructions=executed_instructions_total,
            processed_states=processed_states_count,
        )
        if not self.states_to_explore:
            logger.info("All states explored.")
        else:
            logger.warning(
                f"Max paths ({max_paths}) reached, {len(self.states_to_explore)} states remaining."
            )

        return self.execution_paths

    def _check_satisfiability(self, constraints: List[PathConstraint]) -> bool:
        # Delegate to the solver context
        return self.solver_context.check_satisfiability(constraints)

    # --- Placeholder for Opcode Handlers ---
    # In a real implementation, these would be methods of SymbolicExecutor or in a separate module.
    # --- Opcode Handler Methods (Placeholders) ---
    # These methods will modify the state object directly or return branching/termination info

    def _handle_unimplemented(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Generic handler for unimplemented opcodes."""
        logger.warning(
            "Opcode not implemented",
            opcode=instruction.opcode_info.mnemonic,
            pc=instruction.offset,
        )
        raise NotImplementedError(
            f"Opcode {instruction.opcode_info.mnemonic} (0x{instruction.opcode:02x}) not implemented."
        )

    # 0s: Stop and Arithmetic Operations
    def _handle_stop(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        logger.debug("STOP executed", pc=instruction.offset)
        return {"terminated": True, "reason": "STOP"}

    def _handle_add(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles ADD opcode."""
        if len(state.stack) < 2:
            raise IndexError("ADD Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 + op2  # Uses SymbolicValue.__add__
        state.stack.append(result)
        logger.debug("ADD executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_mul(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles MUL opcode."""
        if len(state.stack) < 2:
            raise IndexError("MUL Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 * op2  # Uses SymbolicValue.__mul__
        state.stack.append(result)
        logger.debug("MUL executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_sub(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles SUB opcode."""
        if len(state.stack) < 2:
            raise IndexError("SUB Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 - op2  # Uses SymbolicValue.__sub__
        state.stack.append(result)
        logger.debug("SUB executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_div(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)  # Unsigned division

    def _handle_sdiv(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)  # Signed division

    def _handle_mod(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_smod(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_addmod(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_mulmod(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_exp(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_signextend(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement SIGNEXTEND

    # 10s: Comparison & Bitwise Logic Operations
    def _handle_lt(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles LT opcode (unsigned less than)."""
        if len(state.stack) < 2:
            raise IndexError("LT Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 < op2  # Uses SymbolicValue.__lt__ -> ULE
        state.stack.append(result)
        logger.debug("LT executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_gt(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles GT opcode (unsigned greater than)."""
        if len(state.stack) < 2:
            raise IndexError("GT Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 > op2  # Uses SymbolicValue.__gt__ -> UGT
        state.stack.append(result)
        logger.debug("GT executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_slt(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement SLT (signed)

    def _handle_sgt(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement SGT (signed)

    def _handle_eq(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles EQ opcode."""
        if len(state.stack) < 2:
            raise IndexError("EQ Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 == op2  # Uses SymbolicValue.__eq__
        state.stack.append(result)
        logger.debug("EQ executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_iszero(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles ISZERO opcode."""
        if len(state.stack) < 1:
            raise IndexError("ISZERO Error: Stack underflow")
        op1 = state.stack.pop()
        result = op1 == 0  # Compare with concrete 0
        state.stack.append(result)
        logger.debug("ISZERO executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_and(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles AND opcode."""
        if len(state.stack) < 2:
            raise IndexError("AND Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 & op2  # Uses SymbolicValue.__and__
        state.stack.append(result)
        logger.debug("AND executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_or(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles OR opcode."""
        if len(state.stack) < 2:
            raise IndexError("OR Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 | op2  # Uses SymbolicValue.__or__
        state.stack.append(result)
        logger.debug("OR executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_xor(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles XOR opcode."""
        if len(state.stack) < 2:
            raise IndexError("XOR Error: Stack underflow")
        op1 = state.stack.pop()
        op2 = state.stack.pop()
        result = op1 ^ op2  # Uses SymbolicValue.__xor__
        state.stack.append(result)
        logger.debug("XOR executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_not(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles NOT opcode."""
        if len(state.stack) < 1:
            raise IndexError("NOT Error: Stack underflow")
        op1 = state.stack.pop()
        result = ~op1  # Uses SymbolicValue.__invert__
        state.stack.append(result)
        logger.debug("NOT executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_byte(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)  # TODO: Implement BYTE

    def _handle_shl(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)  # TODO: Implement SHL

    def _handle_shr(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_sar(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    # 20s: SHA3
    def _handle_sha3(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement SHA3 (KECCAK256)

    # 30s: Environmental Information
    def _handle_address(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles ADDRESS opcode. Pushes the address of the current contract."""
        address_val = state.registers.get("ADDRESS")
        if address_val is None:
            raise ValueError("ADDRESS missing from initial state")
        state.stack.append(address_val)
        logger.debug("ADDRESS executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_balance(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement BALANCE (requires external state lookup or symbolic modeling)

    def _handle_origin(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles ORIGIN opcode. Pushes the transaction origin address."""
        origin_val = state.registers.get("ORIGIN")
        if origin_val is None:
            raise ValueError("ORIGIN missing from initial state")
        state.stack.append(origin_val)
        logger.debug("ORIGIN executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_caller(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles CALLER opcode. Pushes the immediate caller address."""
        caller_val = state.registers.get("CALLER")
        if caller_val is None:
            raise ValueError("CALLER missing from initial state")
        state.stack.append(caller_val)
        logger.debug("CALLER executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_callvalue(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles CALLVALUE opcode. Pushes the value sent with the call."""
        callvalue_val = state.registers.get("CALLVALUE")
        if callvalue_val is None:
            raise ValueError("CALLVALUE missing from initial state")
        state.stack.append(callvalue_val)
        logger.debug("CALLVALUE executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_calldataload(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles CALLDATALOAD opcode. Reads 32 bytes from calldata."""
        if len(state.stack) < 1:
            raise IndexError("CALLDATALOAD Error: Stack underflow")
        offset_sv = state.stack.pop()

        calldata_hex = state.registers.get("CALLDATA")
        if calldata_hex is None:
            raise ValueError("CALLDATA missing from initial state")
        # Ensure it's the hex string we stored, not a SymbolicValue
        if not isinstance(calldata_hex, str):
            raise TypeError("Expected CALLDATA register to be a hex string")
        calldata_bytes = bytes.fromhex(calldata_hex)

        if not offset_sv.is_concrete():
            # Symbolic offset - return a symbolic variable representing the loaded data
            logger.warning(
                "Symbolic CALLDATALOAD offset encountered, returning symbolic value.",
                pc=instruction.offset,
            )
            result = self.create_symbolic_variable(f"calldata_{instruction.offset}")
            state.stack.append(result)
            return {"next_state": state}

        offset = offset_sv.get_concrete_value()
        if offset is None:
            raise TypeError(
                "CALLDATALOAD offset is concrete but get_concrete_value returned None"
            )

        # Read 32 bytes from calldata_bytes starting at offset
        # Handle out-of-bounds reads by padding with zeros
        start = offset
        end = offset + 32
        if start >= len(calldata_bytes):
            word_bytes = bytes(32)  # Read past end -> all zeros
        elif end > len(calldata_bytes):
            word_bytes = calldata_bytes[start:] + bytes(
                end - len(calldata_bytes)
            )  # Read partial + padding
        else:
            word_bytes = calldata_bytes[start:end]

        value_int = int.from_bytes(word_bytes, "big")
        result = self.create_concrete_value(value_int)
        state.stack.append(result)
        logger.debug("CALLDATALOAD executed", offset=offset, pc=instruction.offset)
        return {"next_state": state}

    def _handle_calldatasize(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles CALLDATASIZE opcode. Pushes the size of calldata."""
        calldatasize_val = state.registers.get("CALLDATASIZE")
        if calldatasize_val is None:
            raise ValueError("CALLDATASIZE missing from initial state")
        state.stack.append(calldatasize_val)
        logger.debug("CALLDATASIZE executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_calldatacopy(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement CALLDATACOPY

    def _handle_codesize(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement CODESIZE

    def _handle_codecopy(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_gasprice(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_extcodesize(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_extcodecopy(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_returndatasize(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_returndatacopy(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_extcodehash(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    # 40s: Block Information
    def _handle_blockhash(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement BLOCKHASH (needs access to historical block hashes)

    def _handle_coinbase(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles COINBASE opcode. Pushes the current block's beneficiary address."""
        coinbase_val = state.registers.get("COINBASE")
        if coinbase_val is None:
            raise ValueError("COINBASE missing from initial state")
        state.stack.append(coinbase_val)
        logger.debug("COINBASE executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_timestamp(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles TIMESTAMP opcode. Pushes the current block's timestamp."""
        timestamp_val = state.registers.get("TIMESTAMP")
        if timestamp_val is None:
            raise ValueError("TIMESTAMP missing from initial state")
        state.stack.append(timestamp_val)
        logger.debug("TIMESTAMP executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_number(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles NUMBER opcode. Pushes the current block number."""
        number_val = state.registers.get("NUMBER")
        if number_val is None:
            raise ValueError("NUMBER missing from initial state")
        state.stack.append(number_val)
        logger.debug("NUMBER executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_difficulty(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles DIFFICULTY/PREVRANDAO opcode."""
        difficulty_val = state.registers.get("DIFFICULTY")
        if difficulty_val is None:
            raise ValueError("DIFFICULTY/PREVRANDAO missing from initial state")
        state.stack.append(difficulty_val)
        logger.debug("DIFFICULTY/PREVRANDAO executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_gaslimit(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles GASLIMIT opcode. Pushes the current block's gas limit."""
        gaslimit_val = state.registers.get("GASLIMIT")
        if gaslimit_val is None:
            raise ValueError("GASLIMIT missing from initial state")
        state.stack.append(gaslimit_val)
        logger.debug("GASLIMIT executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_chainid(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement CHAINID (needs chain ID from context)

    def _handle_selfbalance(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(
            instruction, state
        )  # TODO: Implement SELFBALANCE

    def _handle_basefee(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles BASEFEE opcode. Pushes the current block's base fee."""
        basefee_val = state.registers.get("BASEFEE")
        if basefee_val is None:
            raise ValueError("BASEFEE missing from initial state")
        state.stack.append(basefee_val)
        logger.debug("BASEFEE executed", pc=instruction.offset)
        return {"next_state": state}

    # 50s: Stack, Memory, Storage and Flow Operations
    def _handle_pop(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles POP opcode."""
        if not state.stack:
            raise IndexError("POP Error: Stack underflow")
        state.stack.pop()
        logger.debug("POP executed", pc=instruction.offset)
        return {"next_state": state}

    def _handle_mload(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles MLOAD opcode. Reads 32 bytes from memory."""
        if len(state.stack) < 1:
            raise IndexError("MLOAD Error: Stack underflow")
        offset_sv = state.stack.pop()

        if not offset_sv.is_concrete():
            # TODO: Handle symbolic memory offset - complex!
            # For now, create a symbolic variable representing the loaded value.
            logger.warning(
                "Symbolic MLOAD offset encountered, returning symbolic value.",
                pc=instruction.offset,
            )
            result = self.create_symbolic_variable(
                f"mem_{instruction.offset}_{state.current_address}"
            )
            state.stack.append(result)
            return {"next_state": state}

        offset = offset_sv.get_concrete_value()
        if (
            offset is None
        ):  # Should not happen after is_concrete check, but satisfy type checker
            raise TypeError(
                "MLOAD offset is concrete but get_concrete_value returned None"
            )

        # Simple model: Read a 32-byte word starting at offset. Ignores partial reads/overlaps.
        # A better model would use byte arrays or Z3 arrays.
        value = state.memory.get(
            offset, self.create_concrete_value(0)
        )  # Default to 0 if uninitialized
        state.stack.append(value)
        logger.debug("MLOAD executed", offset=offset, pc=instruction.offset)
        return {"next_state": state}

    def _handle_mstore(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles MSTORE opcode. Writes 32 bytes to memory."""
        if len(state.stack) < 2:
            raise IndexError("MSTORE Error: Stack underflow")
        offset_sv = state.stack.pop()
        value_sv = state.stack.pop()

        if not offset_sv.is_concrete():
            # TODO: Handle symbolic memory offset for MSTORE. Very complex.
            # Could taint memory or stop analysis. For now, log and skip write.
            logger.error(
                "Symbolic MSTORE offset encountered. Memory state may be inaccurate.",
                pc=instruction.offset,
            )
            return {"next_state": state}  # Continue, but memory is potentially wrong

        offset = offset_sv.get_concrete_value()
        if offset is None:  # Should not happen after is_concrete check
            raise TypeError(
                "MSTORE offset is concrete but get_concrete_value returned None"
            )

        # Simple model: Store the 32-byte value at the offset. Overwrites anything there.
        state.memory[offset] = value_sv
        logger.debug("MSTORE executed", offset=offset, pc=instruction.offset)
        # TODO: Handle memory expansion cost/logic if tracking gas symbolically
        return {"next_state": state}

    def _handle_mstore8(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles MSTORE8 opcode. Writes a single byte to memory."""
        if len(state.stack) < 2:
            raise IndexError("MSTORE8 Error: Stack underflow")
        offset_sv = state.stack.pop()
        value_sv = state.stack.pop()  # This is a 256-bit value

        if not offset_sv.is_concrete():
            logger.error(
                "Symbolic MSTORE8 offset encountered. Memory state may be inaccurate.",
                pc=instruction.offset,
            )
            return {"next_state": state}

        offset = offset_sv.get_concrete_value()
        if offset is None:  # Should not happen after is_concrete check
            raise TypeError(
                "MSTORE8 offset is concrete but get_concrete_value returned None"
            )

        # Take the least significant byte of the value
        if value_sv.is_concrete():
            concrete_val = value_sv.get_concrete_value()
            if concrete_val is None:  # Should not happen
                raise TypeError(
                    "MSTORE8 value is concrete but get_concrete_value returned None"
                )
            byte_value_int = concrete_val & 0xFF
            byte_value = self.create_concrete_value(byte_value_int, size=8)
        else:
            # Extract the least significant byte symbolically using Z3
            value_expr = value_sv.to_z3(self.solver_context)
            byte_expr = z3.Extract(7, 0, value_expr)
            byte_value = SymbolicValue(
                type=SymbolicType.EXPRESSION, expression=byte_expr, size=8
            )

        # Simple model: Store the byte value. This overwrites the specific byte.
        # A dict[int, SymbolicValue(size=8)] might be better, but MLOAD reads 32 bytes.
        # Current model stores full words, so MSTORE8 is tricky.
        # For now, we'll store it, but MLOAD needs refinement to handle this.
        # A common simplification is to ignore MSTORE8 or treat it like MSTORE.
        # Let's log a warning and store the 8-bit value (which might break MLOAD).
        logger.warning(
            "MSTORE8 implemented simplistically. MLOAD may not read correctly.",
            pc=instruction.offset,
        )
        state.memory[offset] = (
            byte_value  # Storing an 8-bit value where MLOAD expects 256-bit
        )

        logger.debug("MSTORE8 executed", offset=offset, pc=instruction.offset)
        return {"next_state": state}

    def _handle_sload(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles SLOAD opcode. Reads from storage."""
        if len(state.stack) < 1:
            raise IndexError("SLOAD Error: Stack underflow")
        key_sv = state.stack.pop()
        contract_addr = state.current_address  # Use current contract context

        if not key_sv.is_concrete():
            # Symbolic storage key - this is a common case and important for analysis.
            # We return a new symbolic variable representing the value at this symbolic slot.
            # The name should ideally be unique and descriptive.
            key_expr_str = (
                str(key_sv.to_z3(self.solver_context))
                .replace(" ", "_")
                .replace("(", "")
                .replace(")", "")
            )  # Basic sanitization
            var_name = f"storage_{contract_addr}_slot_{key_expr_str[:20]}"  # Truncate long expressions
            logger.warning(
                "Symbolic SLOAD key encountered, returning new symbolic variable.",
                key=key_expr_str,
                var_name=var_name,
                pc=instruction.offset,
            )
            result = self.create_symbolic_variable(var_name)
            state.stack.append(result)
            return {"next_state": state}
        else:
            key = key_sv.get_concrete_value()
            if key is None:
                raise TypeError(
                    "SLOAD key is concrete but get_concrete_value returned None"
                )

            # Get storage for the current contract, default to empty dict if not present
            contract_storage = state.storage.setdefault(contract_addr, {})
            # Get value from storage, default to concrete 0 if slot is uninitialized
            value = contract_storage.get(key, self.create_concrete_value(0))
            state.stack.append(value)
            logger.debug(
                "SLOAD executed",
                key=key,
                value_type=value.type.name,
                pc=instruction.offset,
            )
            return {"next_state": state}

    def _handle_sstore(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles SSTORE opcode. Writes to storage."""
        if len(state.stack) < 2:
            raise IndexError("SSTORE Error: Stack underflow")
        key_sv = state.stack.pop()
        value_sv = state.stack.pop()
        contract_addr = state.current_address

        if not key_sv.is_concrete():
            # Symbolic storage key for SSTORE is very complex to model accurately
            # without advanced techniques like memory models based on Z3 arrays or summaries.
            # Simplification: Log a warning and potentially skip the store or taint the state.
            # Skipping the store is safer but less precise.
            key_expr_str = (
                str(key_sv.to_z3(self.solver_context))
                .replace(" ", "_")
                .replace("(", "")
                .replace(")", "")
            )
            logger.error(
                "Symbolic SSTORE key encountered. State may become inaccurate.",
                key=key_expr_str,
                pc=instruction.offset,
            )
            # Option 1: Skip the store
            return {"next_state": state}
            # Option 2: Taint state (how?) - maybe add a flag?
            # Option 3: Use Z3 Array theory (complex)
        else:
            key = key_sv.get_concrete_value()
            if key is None:
                raise TypeError(
                    "SSTORE key is concrete but get_concrete_value returned None"
                )

            contract_storage = state.storage.setdefault(contract_addr, {})
            contract_storage[key] = value_sv
            logger.debug(
                "SSTORE executed",
                key=key,
                value_type=value_sv.type.name,
                pc=instruction.offset,
            )
            # TODO: Handle gas calculation for SSTORE (warm/cold access, value changes)
            return {"next_state": state}

    def _handle_jump(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles JUMP opcode."""
        if len(state.stack) < 1:
            raise IndexError("JUMP Error: Stack underflow")
        dest_sv = state.stack.pop()

        if not dest_sv.is_concrete():
            logger.error(
                "Symbolic JUMP destination encountered. Terminating path.",
                pc=instruction.offset,
            )
            return {"terminated": True, "reason": "symbolic_jump_destination"}

        dest_pc = dest_sv.get_concrete_value()
        if dest_pc is None:
            raise TypeError(
                "JUMP destination is concrete but get_concrete_value returned None"
            )

        # Need access to the instructions map to check for JUMPDEST
        # This implies execute_symbolic needs to pass it or make it accessible
        # For now, assume we can check validity (will require refactor later)
        # TODO: Refactor to pass 'instructions' map or check validity here
        is_valid_dest = True  # Placeholder - MUST BE CHECKED AGAINST DISASSEMBLY
        # Example check (if instructions map was available):
        # target_instruction = instructions.get(dest_pc)
        # is_valid_dest = target_instruction is not None and target_instruction.opcode_info.mnemonic == 'JUMPDEST'

        if is_valid_dest:
            state.registers["PC"] = self.create_concrete_value(dest_pc, size=64)
            logger.debug("JUMP executed", destination=dest_pc, pc=instruction.offset)
            # Return next_state, but PC is already set for the *next* instruction fetch
            return {"next_state": state}
        else:
            logger.error(
                "Invalid JUMP destination", destination=dest_pc, pc=instruction.offset
            )
            return {"terminated": True, "reason": "invalid_jump_destination"}

    def _handle_jumpi(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles JUMPI opcode."""
        if len(state.stack) < 2:
            raise IndexError("JUMPI Error: Stack underflow")
        dest_sv = state.stack.pop()
        cond_sv = state.stack.pop()

        # --- Handle Concrete Condition ---
        if cond_sv.is_concrete():
            cond_val = cond_sv.get_concrete_value()
            if cond_val is None:
                raise TypeError(
                    "JUMPI condition is concrete but get_concrete_value returned None"
                )

            if cond_val != 0:
                # Condition is true, treat like JUMP
                if not dest_sv.is_concrete():
                    logger.error(
                        "Symbolic JUMPI destination encountered (concrete true condition). Terminating path.",
                        pc=instruction.offset,
                    )
                    return {"terminated": True, "reason": "symbolic_jump_destination"}

                dest_pc = dest_sv.get_concrete_value()
                if dest_pc is None:
                    raise TypeError(
                        "JUMPI destination is concrete but get_concrete_value returned None"
                    )

                # TODO: Check JUMPDEST validity (needs instructions map)
                is_valid_dest = True  # Placeholder
                if is_valid_dest:
                    state.registers["PC"] = self.create_concrete_value(dest_pc, size=64)
                    logger.debug(
                        "JUMPI executed (True branch)",
                        destination=dest_pc,
                        pc=instruction.offset,
                    )
                    return {"next_state": state}
                else:
                    logger.error(
                        "Invalid JUMPI destination (concrete true condition)",
                        destination=dest_pc,
                        pc=instruction.offset,
                    )
                    return {"terminated": True, "reason": "invalid_jump_destination"}
            else:
                # Condition is false, continue sequentially (PC already incremented in main loop)
                logger.debug("JUMPI executed (False branch)", pc=instruction.offset)
                return {"next_state": state}

        # --- Handle Symbolic Condition ---
        else:
            logger.debug(
                "Symbolic JUMPI condition encountered, branching.",
                pc=instruction.offset,
            )
            branch_states_out = []

            # --- Branch 1: Condition is True (non-zero) ---
            state_true = state.clone()
            # Add constraint: cond != 0
            constraint_true = PathConstraint(condition=(cond_sv != 0), taken=True)
            state_true.path_constraints.append(constraint_true)

            # Check destination for true branch
            if not dest_sv.is_concrete():
                logger.error(
                    "Symbolic JUMPI destination encountered (symbolic condition). Terminating TRUE branch.",
                    pc=instruction.offset,
                )
                # We don't add this branch to exploration, effectively terminating it
            else:
                dest_pc_true = dest_sv.get_concrete_value()
                if dest_pc_true is None:
                    raise TypeError(
                        "JUMPI destination is concrete but get_concrete_value returned None"
                    )

                # TODO: Check JUMPDEST validity
                is_valid_dest_true = True  # Placeholder
                if is_valid_dest_true:
                    state_true.registers["PC"] = self.create_concrete_value(
                        dest_pc_true, size=64
                    )
                    # Check satisfiability *before* adding to potential branches
                    if self.solver_context.check_satisfiability(
                        state_true.path_constraints
                    ):
                        branch_states_out.append(state_true)
                        logger.debug(
                            "JUMPI: Added TRUE branch",
                            destination=dest_pc_true,
                            pc=instruction.offset,
                        )
                    else:
                        logger.debug(
                            "JUMPI: Pruning unsatisfiable TRUE branch",
                            pc=instruction.offset,
                        )
                else:
                    logger.error(
                        "Invalid JUMPI destination (symbolic condition, true branch)",
                        destination=dest_pc_true,
                        pc=instruction.offset,
                    )
                    # Terminate this potential branch by not adding it

            # --- Branch 2: Condition is False (zero) ---
            state_false = state.clone()
            # Add constraint: cond == 0
            constraint_false = PathConstraint(condition=(cond_sv == 0), taken=True)
            state_false.path_constraints.append(constraint_false)
            # PC for false branch is already incremented past JUMPI in the main loop, no PC update needed here

            # Check satisfiability *before* adding to potential branches
            if self.solver_context.check_satisfiability(state_false.path_constraints):
                branch_states_out.append(state_false)
                logger.debug("JUMPI: Added FALSE branch", pc=instruction.offset)
            else:
                logger.debug(
                    "JUMPI: Pruning unsatisfiable FALSE branch", pc=instruction.offset
                )

            # Return the list of satisfiable and valid branches
            return {"branch_states": branch_states_out}

    def _handle_pc(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles PC opcode."""
        # PC is the address of the *current* instruction
        pc_value = instruction.offset
        state.stack.append(
            self.create_concrete_value(pc_value, size=64)
        )  # PC is often treated as 64-bit
        logger.debug("PC executed", value=pc_value, pc=instruction.offset)
        return {"next_state": state}

    def _handle_msize(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_gas(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_jumpdest(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return {"next_state": state}  # JUMPDEST is a no-op

    # 60s & 70s: Push Operations
    def _handle_push(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles PUSH1-PUSH32 opcodes."""
        if instruction.operand is None:
            # This shouldn't happen for PUSH opcodes parsed by evmole
            logger.error("PUSH instruction missing operand", pc=instruction.offset)
            raise ValueError("PUSH instruction operand is None")

        # Operand is bytes, convert to int
        value = int.from_bytes(instruction.operand, "big")
        size_in_bits = instruction.operand_size * 8
        pushed_value = self.create_concrete_value(value, size=size_in_bits)

        state.stack.append(pushed_value)
        logger.debug(
            "PUSH executed", value=value, size=size_in_bits, pc=instruction.offset
        )
        return {"next_state": state}  # Continue sequential execution

    # 80s: Duplication Operations
    def _handle_dup(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles DUP1-DUP16 opcodes."""
        # Opcode 0x80 is DUP1, 0x8f is DUP16
        dup_n = instruction.opcode - 0x80 + 1
        if not 1 <= dup_n <= 16:
            raise ValueError(
                f"Invalid DUP instruction: {instruction.opcode_info.mnemonic}"
            )
        if len(state.stack) < dup_n:
            raise IndexError(f"DUP{dup_n} Error: Stack underflow")

        value_to_dup = state.stack[-dup_n]  # Get the Nth item from the top
        state.stack.append(value_to_dup)  # Push a copy onto the stack
        logger.debug(f"DUP{dup_n} executed", pc=instruction.offset)
        return {"next_state": state}

    # 90s: Exchange Operations
    def _handle_swap(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        """Handles SWAP1-SWAP16 opcodes."""
        # Opcode 0x90 is SWAP1, 0x9f is SWAP16
        swap_n = instruction.opcode - 0x90 + 1
        if not 1 <= swap_n <= 16:
            raise ValueError(
                f"Invalid SWAP instruction: {instruction.opcode_info.mnemonic}"
            )
        if len(state.stack) < swap_n + 1:
            raise IndexError(f"SWAP{swap_n} Error: Stack underflow")

        # Swap top element with the (N+1)th element from the top
        idx_n_plus_1 = -(swap_n + 1)
        state.stack[-1], state.stack[idx_n_plus_1] = (
            state.stack[idx_n_plus_1],
            state.stack[-1],
        )
        logger.debug(f"SWAP{swap_n} executed", pc=instruction.offset)
        return {"next_state": state}

    # a0s: Logging Operations
    def _handle_log(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    # f0s: System operations
    def _handle_create(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_call(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_callcode(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_return(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return {"terminated": True, "reason": "RETURN"}

    def _handle_delegatecall(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_create2(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_staticcall(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return self._handle_unimplemented(instruction, state)

    def _handle_revert(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return {"terminated": True, "reason": "REVERT"}

    def _handle_invalid(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return {"terminated": True, "reason": "INVALID"}

    def _handle_selfdestruct(
        self, instruction: Instruction, state: SymbolicEVMState
    ) -> Dict[str, Any]:
        return {"terminated": True, "reason": "SELFDESTRUCT"}
