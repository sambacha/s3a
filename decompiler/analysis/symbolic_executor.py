import z3
import sys
from typing import List, Dict, Optional, Tuple, Union, Any

# Assuming analyze_stack_locally has populated block.stack_effect = (pushes, pops)
# and block.stack_height_in (required input height for the block)
from ..core.instruction import Instruction
from ..core.basic_block import BasicBlock
from .stack_analyzer import OPCODE_STACK_EFFECTS
from ..utils.evm_ops import *
from ..disassembler import get_instruction_size

# Enhanced Symbolic Value for jump analysis
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
    
    # Helper methods for operations
    def add(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Add two symbolic values."""
        result = evm_add(self.value, other.value)
        return SymbolicValue(value=result)
    
    def sub(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Subtract other from self."""
        result = evm_sub(self.value, other.value)
        return SymbolicValue(value=result)
    
    def mul(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Multiply two symbolic values."""
        result = evm_mul(self.value, other.value)
        return SymbolicValue(value=result)
    
    def div(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Divide self by other."""
        result = evm_div(self.value, other.value)
        return SymbolicValue(value=result)
    
    def sdiv(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Signed divide self by other."""
        result = evm_sdiv(self.value, other.value)
        return SymbolicValue(value=result)
    
    def mod(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Modulo self by other."""
        result = evm_mod(self.value, other.value)
        return SymbolicValue(value=result)
    
    def smod(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Signed modulo self by other."""
        result = evm_smod(self.value, other.value)
        return SymbolicValue(value=result)
    
    def addmod(self, other: 'SymbolicValue', modulus: 'SymbolicValue') -> 'SymbolicValue':
        """(self + other) % modulus."""
        result = evm_addmod(self.value, other.value, modulus.value)
        return SymbolicValue(value=result)
    
    def mulmod(self, other: 'SymbolicValue', modulus: 'SymbolicValue') -> 'SymbolicValue':
        """(self * other) % modulus."""
        result = evm_mulmod(self.value, other.value, modulus.value)
        return SymbolicValue(value=result)
    
    def exp(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """self ^ other."""
        result = evm_exp(self.value, other.value)
        return SymbolicValue(value=result)
    
    def lt(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Less than comparison."""
        result = evm_lt(self.value, other.value)
        return SymbolicValue(value=result)
    
    def gt(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Greater than comparison."""
        result = evm_gt(self.value, other.value)
        return SymbolicValue(value=result)
    
    def slt(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Signed less than comparison."""
        result = evm_slt(self.value, other.value)
        return SymbolicValue(value=result)
    
    def sgt(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Signed greater than comparison."""
        result = evm_sgt(self.value, other.value)
        return SymbolicValue(value=result)
    
    def eq(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Equal comparison."""
        result = evm_eq(self.value, other.value)
        return SymbolicValue(value=result)
    
    def iszero(self) -> 'SymbolicValue':
        """Is zero check."""
        result = evm_iszero(self.value)
        return SymbolicValue(value=result)
    
    def and_op(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Bitwise AND."""
        result = evm_and(self.value, other.value)
        return SymbolicValue(value=result)
    
    def or_op(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Bitwise OR."""
        result = evm_or(self.value, other.value)
        return SymbolicValue(value=result)
    
    def xor(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Bitwise XOR."""
        result = evm_xor(self.value, other.value)
        return SymbolicValue(value=result)
    
    def not_op(self) -> 'SymbolicValue':
        """Bitwise NOT."""
        result = evm_not(self.value)
        return SymbolicValue(value=result)
    
    def byte_op(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Get the nth byte of other, where n is self."""
        try:
            result = evm_byte(self.value, other.value)
            return SymbolicValue(value=result)
        except Exception:
            # Fallback for cases where symbolic execution of byte is challenging
            return SymbolicValue()
    
    def shl(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Self << other."""
        result = evm_shl(self.value, other.value)
        return SymbolicValue(value=result)
    
    def shr(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Self >> other (logical)."""
        result = evm_shr(self.value, other.value)
        return SymbolicValue(value=result)
    
    def sar(self, other: 'SymbolicValue') -> 'SymbolicValue':
        """Self >> other (arithmetic)."""
        result = evm_sar(self.value, other.value)
        return SymbolicValue(value=result)

# Enhanced Execution State
class ExecutionState:
    """Represents the state during symbolic execution (stack, memory, storage)."""
    def __init__(self, pc: int = 0, stack: Optional[List[SymbolicValue]] = None, 
                 memory: Optional[Dict[int, SymbolicValue]] = None,
                 storage: Optional[Dict[Any, SymbolicValue]] = None,
                 calldata: Optional[Dict[int, SymbolicValue]] = None):
        self.pc = pc
        self.stack = stack if stack is not None else []
        self.memory = memory if memory is not None else {} # Simplified memory model for now
        self.storage = storage if storage is not None else {} # Simplified storage model
        self.calldata = calldata if calldata is not None else {} # Simplified calldata model

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

    def memory_read(self, addr: SymbolicValue, size: Optional[SymbolicValue] = None) -> SymbolicValue:
        """Read from memory at the given address."""
        addr_val = addr.get_concrete_value()
        if addr_val is not None:
            if addr_val in self.memory:
                return self.memory[addr_val]
        # Return a new symbolic value for unknown memory locations or symbolic addresses
        return SymbolicValue()
    
    def memory_write(self, addr: SymbolicValue, value: SymbolicValue):
        """Write to memory at the given address."""
        addr_val = addr.get_concrete_value()
        if addr_val is not None:
            self.memory[addr_val] = value
    
    def storage_read(self, key: SymbolicValue) -> SymbolicValue:
        """Read from storage at the given key."""
        key_val = key.get_concrete_value()
        if key_val is not None:
            if key_val in self.storage:
                return self.storage[key_val]
        # Return a new symbolic value for unknown storage keys
        return SymbolicValue()
    
    def storage_write(self, key: SymbolicValue, value: SymbolicValue):
        """Write to storage at the given key."""
        key_val = key.get_concrete_value()
        if key_val is not None:
            self.storage[key_val] = value
    
    def calldata_read(self, offset: SymbolicValue, size: Optional[SymbolicValue] = None) -> SymbolicValue:
        """Read from calldata at the given offset."""
        offset_val = offset.get_concrete_value()
        if offset_val is not None:
            if offset_val in self.calldata:
                return self.calldata[offset_val]
        # Return a new symbolic value for unknown calldata
        return SymbolicValue()

    def clone(self) -> 'ExecutionState':
        """Create a deep copy of the current state."""
        new_state = ExecutionState(
            pc=self.pc,
            stack=self.stack.copy(),
            memory=self.memory.copy(),
            storage=self.storage.copy(),
            calldata=self.calldata.copy()
        )
        return new_state

# Enhanced Symbolic Executor Class Structure
class SymbolicExecutor:
    def __init__(self, all_blocks: Dict[int, BasicBlock], instr_map_raw: Dict[int, 'PyevmInstruction']):
        self.all_blocks = all_blocks
        self.instr_map_raw = instr_map_raw # Needed for instruction size
        self.var_counter = 0 # Counter for creating unique symbolic variables
    
    def create_symbolic_variable(self, name_hint: str = 'sym') -> SymbolicValue:
        """Create a new symbolic variable with a unique name."""
        self.var_counter += 1
        var = z3.BitVec(f"{name_hint}_{self.var_counter}", 256)
        return SymbolicValue(value=var)

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
            # Arithmetic Operations
            elif opcode == "ADD":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.add(op2))
            elif opcode == "SUB":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.sub(op2))
            elif opcode == "MUL":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.mul(op2))
            elif opcode == "DIV":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.div(op2))
            elif opcode == "SDIV":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.sdiv(op2))
            elif opcode == "MOD":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.mod(op2))
            elif opcode == "SMOD":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.smod(op2))
            elif opcode == "ADDMOD":
                op3 = state.pop()
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.addmod(op2, op3))
            elif opcode == "MULMOD":
                op3 = state.pop()
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.mulmod(op2, op3))
            elif opcode == "EXP":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.exp(op2))
            # Comparison Operations
            elif opcode == "LT":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.lt(op2))
            elif opcode == "GT":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.gt(op2))
            elif opcode == "SLT":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.slt(op2))
            elif opcode == "SGT":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.sgt(op2))
            elif opcode == "EQ":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.eq(op2))
            elif opcode == "ISZERO":
                op1 = state.pop()
                state.push(op1.iszero())
            # Bitwise Operations
            elif opcode == "AND":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.and_op(op2))
            elif opcode == "OR":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.or_op(op2))
            elif opcode == "XOR":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.xor(op2))
            elif opcode == "NOT":
                op1 = state.pop()
                state.push(op1.not_op())
            elif opcode == "BYTE":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.byte_op(op2))
            elif opcode == "SHL":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.shl(op2))
            elif opcode == "SHR":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.shr(op2))
            elif opcode == "SAR":
                op2 = state.pop()
                op1 = state.pop()
                state.push(op1.sar(op2))
            # Memory Operations
            elif opcode == "MLOAD":
                addr = state.pop()
                value = state.memory_read(addr)
                state.push(value)
            elif opcode == "MSTORE":
                addr = state.pop()
                value = state.pop()
                state.memory_write(addr, value)
            elif opcode == "MSTORE8":
                addr = state.pop()
                value = state.pop()
                # Store only the lowest byte
                state.memory_write(addr, value)  # Simplified - should only store 1 byte
            # Storage Operations
            elif opcode == "SLOAD":
                key = state.pop()
                value = state.storage_read(key)
                state.push(value)
            elif opcode == "SSTORE":
                key = state.pop()
                value = state.pop()
                state.storage_write(key, value)
            # Environment Operations
            elif opcode == "ADDRESS":
                # Get the address of the current contract
                state.push(self.create_symbolic_variable("CONTRACT_ADDRESS"))
            elif opcode == "BALANCE":
                addr = state.pop()
                # Get balance of the specified address
                state.push(self.create_symbolic_variable(f"BALANCE_OF_{addr}"))
            elif opcode == "ORIGIN":
                # Get the transaction origin address
                state.push(self.create_symbolic_variable("TX_ORIGIN"))
            elif opcode == "CALLER":
                # Get the caller address
                state.push(self.create_symbolic_variable("MSG_SENDER"))
            elif opcode == "CALLVALUE":
                # Get the call value
                state.push(self.create_symbolic_variable("MSG_VALUE"))
            elif opcode == "CALLDATALOAD":
                offset = state.pop()
                value = state.calldata_read(offset)
                state.push(value)
            elif opcode == "CALLDATASIZE":
                # Get calldata size
                state.push(self.create_symbolic_variable("CALLDATA_SIZE"))
            elif opcode == "CALLDATACOPY":
                dest_offset = state.pop()
                offset = state.pop()
                size = state.pop()
                # FIXME: Implement actual memory updates for CALLDATACOPY
                pass
            # Control flow - JUMP/JUMPI
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
                 for _ in range(pushes): state.push(self.create_symbolic_variable(f"{opcode}_RESULT")) # Push symbolic values

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
