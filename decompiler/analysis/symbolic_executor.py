import z3
import sys
from typing import List, Dict, Optional, Tuple, Union

# Assuming analyze_stack_locally has populated block.stack_effect = (pushes, pops)
# and block.stack_height_in (required input height for the block)
from ..core.instruction import Instruction
from ..core.basic_block import BasicBlock
from .stack_analyzer import OPCODE_STACK_EFFECTS

# Simplified Symbolic Value for jump analysis
class SymbolicValue:
    """Represents a value that can be either concrete (int) or symbolic (z3 BitVec)."""
    def __init__(self, value: Optional[Union[int, z3.BitVecRef]] = None, is_concrete: Optional[bool] = None):
        if is_concrete is not None:
            self.concrete = is_concrete
            self.value = value
        elif isinstance(value, int):
            self.concrete = True
            # Ensure concrete values are also 256-bit
            self.value = z3.BitVecVal(value, 256)
        elif isinstance(value, z3.BitVecRef):
            self.concrete = False
            self.value = value
        else: # Default to a new symbolic variable
            self.concrete = False
            self.value = z3.BitVec(f"sym_{id(self)}", 256)

    @property
    def is_symbolic(self) -> bool:
        return not self.concrete

    def get_concrete_value(self) -> Optional[int]:
        """Returns the concrete integer value if known, otherwise None."""
        if self.concrete and isinstance(self.value, z3.BitVecNumRef):
             # Extract integer value from Z3 BitVecVal
             try:
                 return self.value.as_long()
             except:
                 return None # Should not happen for BitVecVal
        # Check if a symbolic value can be simplified to a constant
        elif not self.concrete and isinstance(self.value, z3.BitVecNumRef):
             try:
                 # This might happen if z3 simplifies an expression to a constant
                 self.concrete = True
                 return self.value.as_long()
             except:
                 return None
        return None


    def __str__(self) -> str:
        concrete_val = self.get_concrete_value()
        if concrete_val is not None:
            return hex(concrete_val)
        else:
            # Simplify Z3 expression for readability if possible
            try:
                simplified_expr = z3.simplify(self.value)
                return str(simplified_expr)
            except:
                return str(self.value) # Fallback to default string representation

    def __repr__(self) -> str:
        return f"SymVal({self.value}, concrete={self.concrete})"

# Simplified Execution State
class ExecutionState:
    """Represents the state during symbolic execution (stack, memory)."""
    def __init__(self, pc: int = 0, stack: Optional[List[SymbolicValue]] = None, memory: Optional[Dict[int, SymbolicValue]] = None):
        self.pc = pc
        self.stack = stack if stack is not None else []
        self.memory = memory if memory is not None else {} # Simplified memory model for now

    def push(self, value: Union[int, z3.BitVecRef, SymbolicValue]):
        if isinstance(value, SymbolicValue):
            self.stack.append(value)
        elif isinstance(value, int):
            self.stack.append(SymbolicValue(value=value))
        elif isinstance(value, z3.BitVecRef):
             # Check if it's actually a concrete value wrapped by Z3
             if isinstance(value, z3.BitVecNumRef):
                 self.stack.append(SymbolicValue(value=value.as_long()))
             else:
                 self.stack.append(SymbolicValue(value=value))
        else:
             raise TypeError("Cannot push non-symbolic/int/z3 value onto stack")


    def pop(self) -> SymbolicValue:
        if not self.stack:
            # Stack underflow - return a new symbolic value
            # print("[Warning] Stack underflow during pop", file=sys.stderr)
            return SymbolicValue()
        return self.stack.pop()

    def peek(self, index: int = 0) -> SymbolicValue:
        """Access stack item without popping (0 is top)."""
        if index < 0 or index >= len(self.stack):
             # print(f"[Warning] Stack peek underflow/invalid index {index}", file=sys.stderr)
             return SymbolicValue() # Return new symbolic value on underflow/invalid index
        return self.stack[-(index + 1)]


    def clone(self) -> 'ExecutionState':
        new_state = ExecutionState(
            pc=self.pc,
            stack=self.stack.copy(),
            memory=self.memory.copy() # Shallow copy ok if SymbolicValues are immutable enough
        )
        return new_state

# Bounded Symbolic Executor Class Structure
class SymbolicExecutor:
    def __init__(self, all_blocks: Dict[int, BasicBlock], instr_map_raw: Dict[int, PyevmInstruction]):
        self.all_blocks = all_blocks
        self.instr_map_raw = instr_map_raw # Needed for instruction size

    def execute_block_symbolically(self, block: BasicBlock, initial_state: ExecutionState) -> ExecutionState:
        """Symbolically execute instructions within a single basic block."""
        state = initial_state.clone()

        for instr in block.instructions:
            state.pc = instr.offset
            opcode = instr.opcode
            # print(f"[SymExec Debug] Executing {opcode} at {hex(state.pc)}", file=sys.stderr)
            # print(f"[SymExec Debug] Stack before: {[str(s) for s in state.stack]}", file=sys.stderr)

            raw_instr = self.instr_map_raw.get(instr.offset)
            next_pc = state.pc + get_instruction_size(raw_instr) if raw_instr else state.pc + 1

            # --- Handle Opcodes ---
            if opcode.startswith("PUSH"):
                val = instr.operands[0] if instr.operands else 0
                state.push(val)
            elif opcode.startswith("DUP"):
                dup_n = int(opcode[3:])
                state.push(state.peek(dup_n - 1))
            elif opcode.startswith("SWAP"):
                swap_n = int(opcode[4:])
                if len(state.stack) >= swap_n + 1:
                     idx1 = -1
                     idx2 = -(swap_n + 1)
                     state.stack[idx1], state.stack[idx2] = state.stack[idx2], state.stack[idx1]
                # else: underflow, stack unchanged
            elif opcode == "POP":
                state.pop()
            elif opcode == "ADD":
                op1 = state.pop()
                op2 = state.pop()
                state.push(z3.simplify(op1.value + op2.value))
            elif opcode == "SUB":
                op1 = state.pop()
                op2 = state.pop()
                state.push(z3.simplify(op1.value - op2.value))
            elif opcode == "MUL":
                op1 = state.pop()
                op2 = state.pop()
                state.push(z3.simplify(op1.value * op2.value))
            # --- Add more opcode handlers here (DIV, MOD, LT, GT, EQ, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR, MLOAD, MSTORE etc.) ---
            # --- Handle JUMP/JUMPI specifically ---
            elif opcode == "JUMP":
                target_sym = state.pop()
                # Cannot follow jump symbolically here, just record state and stop block execution
                state.pc = next_pc # Update PC to point after JUMP for state analysis
                break
            elif opcode == "JUMPI":
                target_sym = state.pop()
                condition_sym = state.pop()
                # Cannot follow jump symbolically here, just record state and stop block execution
                state.pc = next_pc # Update PC to point after JUMPI for state analysis
                break
            elif opcode in ("STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"):
                 state.pc = next_pc
                 break # Stop execution for this block
            else:
                 # Default handler using OPCODE_STACK_EFFECTS
                 pops, pushes = OPCODE_STACK_EFFECTS.get(opcode, (0, 0))
                 for _ in range(pops): state.pop()
                 for _ in range(pushes): state.push(SymbolicValue()) # Push unknown symbolic values

            # Move to next instruction offset within the block
            state.pc = next_pc
            # print(f"[SymExec Debug] Stack after: {[str(s) for s in state.stack]}", file=sys.stderr)


        return state

    def analyze_jump(self, jump_instr: Instruction, initial_state: ExecutionState) -> Tuple[Optional[int], Optional[z3.BitVecRef]]:
        """
        Analyze the target of a JUMP/JUMPI instruction using bounded symbolic execution
        starting from a given state (typically the state at the entry of the jump's block).

        Returns:
            Tuple (concrete_target, symbolic_target_expr):
            - concrete_target: Integer offset if resolved, else None.
            - symbolic_target_expr: Z3 expression for the target if not concrete, else None.
        """
        if jump_instr.offset not in self.all_blocks:
             print(f"[Warning] Jump instruction offset {hex(jump_instr.offset)} not found in any block.", file=sys.stderr)
             return None, None

        jump_block = self.all_blocks[jump_instr.offset]

        # Execute the block containing the jump symbolically
        final_state = self.execute_block_symbolically(jump_block, initial_state)

        # The target should be the top of the stack *before* the JUMP/JUMPI executed
        # Re-simulate just the jump instruction's pop
        target_sym_val = SymbolicValue() # Default if stack was empty before jump
        if jump_instr.opcode == "JUMP":
             if len(final_state.stack) >= 1: # Check if stack has at least 1 item (the target)
                 # This assumes execute_block_symbolically stopped *before* popping for JUMP
                 target_sym_val = final_state.peek(0)
        elif jump_instr.opcode == "JUMPI":
             if len(final_state.stack) >= 2: # Check if stack has at least 2 items (cond, target)
                 # This assumes execute_block_symbolically stopped *before* popping for JUMPI
                 target_sym_val = final_state.peek(1) # Target is second item

        concrete_target = target_sym_val.get_concrete_value()
        symbolic_target_expr = target_sym_val.value if not target_sym_val.concrete else None

        return concrete_target, symbolic_target_expr

# Example Usage (Conceptual - requires integration)
# executor = SymbolicExecutor(all_basic_blocks, instr_map_raw)
# entry_state = ExecutionState(pc=block_entry_offset, stack=[...]) # Need initial stack state
# concrete, symbolic = executor.analyze_jump(jump_instruction, entry_state)
