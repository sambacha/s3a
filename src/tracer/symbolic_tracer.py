"""
Symbolic execution engine for EVM bytecode analysis.

This module provides the core symbolic execution functionality
for analyzing Ethereum smart contract bytecode and identifying
storage access patterns.
"""

from typing import Dict, List, Optional, Set, Tuple, Union, Any
import z3
import logging
from .evm_opcodes import Opcode, disassemble_bytecode, get_stack_effect

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_MAX_PATHS = 200  # Increased from 50
DEFAULT_MAX_DEPTH = 200  # Increased from 100

class SymbolicValue:
    """Represents a value that can be either concrete or symbolic."""
    
    def __init__(self, value: Optional[int] = None):
        """Initialize with either a concrete value or a symbolic one."""
        self.concrete = value is not None
        self.value = value if value is not None else z3.BitVec(f"sym_{id(self)}", 256)
        
        # Additional metadata for storage analysis
        self.is_keccak = False
        self.keccak_args = None
        self.is_storage_key = False
        self.is_array_index = False
        self.storage_base = None
    
    def __str__(self) -> str:
        if self.concrete:
            return f"{self.value:#x}" if isinstance(self.value, int) else str(self.value)
        else:
            return str(self.value)
    
    def __repr__(self) -> str:
        return self.__str__()
    
    @property
    def is_symbolic(self) -> bool:
        """Check if this value is symbolic rather than concrete."""
        return not self.concrete


class StorageAccess:
    """Records details of storage access operations during execution."""
    
    def __init__(self, op_type: str, slot: SymbolicValue, 
                 value: Optional[SymbolicValue] = None, pc: Optional[int] = None):
        """
        Initialize storage access record.
        
        Args:
            op_type: Either 'SLOAD' or 'SSTORE'
            slot: Storage slot being accessed
            value: Value being stored (for SSTORE operations)
            pc: Program counter where this operation occurred
        """
        self.op_type = op_type
        self.slot = slot
        self.value = value
        self.pc = pc
        
        # Additional metadata for pattern detection
        self.is_mapping = False
        self.is_array = False
        self.base_slot = None
        self.key_type = None
    
    def __str__(self) -> str:
        if self.op_type == 'SLOAD':
            return f"{self.op_type} {self.slot} @ PC {self.pc}"
        else:
            return f"{self.op_type} {self.slot} = {self.value} @ PC {self.pc}"
    
    def __repr__(self) -> str:
        return self.__str__()


class ExecutionState:
    """Represents the execution state during symbolic execution."""
    
    def __init__(self, pc: int = 0):
        """Initialize a new execution state at the given program counter."""
        self.stack: List[SymbolicValue] = []
        self.memory: Dict[int, SymbolicValue] = {}
        self.storage: Dict[int, SymbolicValue] = {}
        self.path_conditions: List[z3.BoolRef] = []
        self.pc = pc
        
        # Track memory regions for better keccak analysis
        self.memory_regions: Dict[Tuple[int, int], List[SymbolicValue]] = {}
    
    def clone(self) -> 'ExecutionState':
        """Create a deep copy of this execution state."""
        new_state = ExecutionState(self.pc)
        new_state.stack = self.stack.copy()
        new_state.memory = self.memory.copy()
        new_state.storage = self.storage.copy()
        new_state.path_conditions = self.path_conditions.copy()
        new_state.memory_regions = self.memory_regions.copy()
        return new_state
    
    def push(self, value: SymbolicValue) -> None:
        """Push a value onto the stack."""
        self.stack.append(value)
    
    def pop(self) -> SymbolicValue:
        """Pop a value from the stack, using a symbolic value for underflow."""
        if not self.stack:
            logger.debug("Stack underflow, using symbolic value")
            return SymbolicValue()
        return self.stack.pop()
    
    def peek(self, index: int = 0) -> SymbolicValue:
        """Access a stack value without removing it."""
        if index >= len(self.stack):
            logger.debug(f"Stack peek underflow at index {index}, using symbolic value")
            return SymbolicValue()
        return self.stack[-(index + 1)]
    
    def store_memory_region(self, offset: int, size: int, values: List[SymbolicValue]) -> None:
        """Store a memory region for later analysis."""
        self.memory_regions[(offset, size)] = values


class SymbolicExecutor:
    """Executes EVM bytecode symbolically to analyze behavior."""
    
    def __init__(self, max_paths: int = DEFAULT_MAX_PATHS, max_depth: int = DEFAULT_MAX_DEPTH):
        """Initialize the symbolic executor with execution bounds."""
        self.solver = z3.Solver()
        self.storage_accesses: List[StorageAccess] = []
        self.execution_paths = 0
        self.max_paths = max_paths
        self.max_depth = max_depth
    
    def analyze(self, bytecode: str) -> List[StorageAccess]:
        """Analyze bytecode to identify storage access patterns."""
        # Reset state
        self.storage_accesses = []
        self.execution_paths = 0
        
        # Validate bytecode
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        # Extract runtime bytecode if this is contract creation bytecode
        runtime_bytecode = self._extract_runtime_bytecode(bytecode)
        if runtime_bytecode:
            logger.info(f"Extracted runtime bytecode of size: {len(runtime_bytecode) // 2} bytes")
            bytecode = runtime_bytecode
        
        # Disassemble bytecode
        operations = disassemble_bytecode(bytecode)
        logger.info(f"Disassembled {len(operations)} operations from bytecode")
        
        # First try direct analysis of storage operations
        direct_accesses = self._direct_storage_analysis(operations)
        if direct_accesses:
            logger.info(f"Direct analysis found {len(direct_accesses)} storage accesses")
            self.storage_accesses = direct_accesses
        else:
            # If direct analysis fails, fall back to symbolic execution
            logger.info("Falling back to symbolic execution")
            # Start execution with initial state
            initial_state = ExecutionState()
            self._execute(operations, initial_state)
        
        # Post-process storage accesses to identify patterns
        self._post_process_storage_accesses()
        
        logger.info(f"Analysis complete: {len(self.storage_accesses)} storage accesses, {self.execution_paths} execution paths")
        return self.storage_accesses
    
    def _direct_storage_analysis(self, operations: List[Tuple[str, int, Optional[bytes], int]]) -> List[StorageAccess]:
        """
        Directly analyze bytecode for storage operations without symbolic execution.
        This is a fallback method that looks for SLOAD and SSTORE operations with
        concrete slot values.
        
        Args:
            operations: List of disassembled operations
            
        Returns:
            List of StorageAccess objects
        """
        accesses = []
        
        # Track the stack for each operation
        stack = []
        
        # Map of known storage slots
        known_slots = {}
        
        for i, (opcode_name, opcode_value, push_data, offset) in enumerate(operations):
            # Handle PUSH operations to track concrete values
            if Opcode.PUSH1 <= opcode_value <= Opcode.PUSH32 and push_data:
                value = int.from_bytes(push_data, byteorder='big')
                stack.append(SymbolicValue(value))
                
                # If this is a small value (likely a storage slot), remember it
                if value < 100:
                    known_slots[i] = value
            
            # Handle DUP operations
            elif Opcode.DUP1 <= opcode_value <= Opcode.DUP16:
                position = opcode_value - Opcode.DUP1
                if len(stack) > position:
                    stack.append(stack[-(position+1)])
                else:
                    stack.append(SymbolicValue())  # Symbolic value for unknown
            
            # Handle SWAP operations
            elif Opcode.SWAP1 <= opcode_value <= Opcode.SWAP16:
                position = opcode_value - Opcode.SWAP1 + 1
                if len(stack) >= position + 1:
                    stack[-1], stack[-(position+1)] = stack[-(position+1)], stack[-1]
            
            # Handle SLOAD operations
            elif opcode_value == Opcode.SLOAD:
                if stack:
                    slot = stack.pop()
                    # Create a storage access record
                    access = StorageAccess('SLOAD', slot, pc=offset)
                    accesses.append(access)
                    logger.debug(f"Direct analysis: SLOAD at PC {offset} for slot {slot}")
                    
                    # Push a symbolic value for the loaded value
                    stack.append(SymbolicValue())
                else:
                    stack.append(SymbolicValue())
            
            # Handle SSTORE operations
            elif opcode_value == Opcode.SSTORE:
                if len(stack) >= 2:
                    value, slot = stack.pop(), stack.pop()
                    # Create a storage access record
                    access = StorageAccess('SSTORE', slot, value, pc=offset)
                    accesses.append(access)
                    logger.debug(f"Direct analysis: SSTORE at PC {offset}: {slot} = {value}")
                
            # Handle other operations that consume stack items
            else:
                stack_in, stack_out = get_stack_effect(opcode_value)
                
                # Pop items from stack
                for _ in range(min(stack_in, len(stack))):
                    stack.pop()
                
                # Push symbolic values to stack
                for _ in range(stack_out):
                    stack.append(SymbolicValue())
        
        # Process the accesses to identify patterns
        for access in accesses:
            # Check for array access patterns (base slot + index)
            if not access.slot.concrete and isinstance(access.slot.value, z3.BitVecRef):
                slot_str = str(access.slot.value)
                if "+" in slot_str and not "keccak256" in slot_str:
                    access.is_array = True
                    logger.debug(f"Direct analysis: Detected array access: {access}")
            
            # Check for mapping access patterns (keccak256 hash)
            elif not access.slot.concrete and isinstance(access.slot.value, z3.BitVecRef):
                slot_str = str(access.slot.value)
                if "keccak256" in slot_str:
                    access.is_mapping = True
                    logger.debug(f"Direct analysis: Detected mapping access: {access}")
        
        return accesses
    
    def _extract_runtime_bytecode(self, bytecode: str) -> Optional[str]:
        """
        Extract runtime bytecode from contract creation bytecode.
        
        Contract creation bytecode typically ends with:
        - PUSH1 <size>
        - DUP1
        - PUSH1/PUSH2 <offset>
        - CODECOPY
        - PUSH1 0
        - RETURN
        - <runtime bytecode>
        
        Args:
            bytecode: Contract creation bytecode
            
        Returns:
            Runtime bytecode if found, None otherwise
        """
        try:
            # Disassemble bytecode
            operations = disassemble_bytecode(bytecode)
            
            # Look for CODECOPY pattern
            for i, (opcode_name, opcode_value, push_data, offset) in enumerate(operations):
                if opcode_name == 'RETURN' and i > 2:
                    # Check if this is the end of initialization code
                    prev_ops = operations[i-3:i]
                    if any(op[0] == 'CODECOPY' for op in prev_ops):
                        # Find the size of the runtime bytecode
                        for j, (op_name, op_value, op_data, op_offset) in enumerate(prev_ops):
                            if op_name.startswith('PUSH') and op_data:
                                size = int.from_bytes(op_data, byteorder='big')
                                # Extract runtime bytecode
                                runtime_start = offset + 1
                                if runtime_start + size * 2 <= len(bytecode):
                                    return bytecode[runtime_start:runtime_start + size * 2]
            
            # Alternative approach: look for the runtime bytecode after the STOP or RETURN
            for i, (opcode_name, opcode_value, push_data, offset) in enumerate(operations):
                if opcode_name in ('STOP', 'RETURN') and offset + 1 < len(bytecode) // 2:
                    # Check if there's more bytecode after this
                    remaining = bytecode[offset * 2 + 2:]
                    if len(remaining) > 64:  # Arbitrary minimum size for runtime bytecode
                        return remaining
            
            # If we can't find the runtime bytecode, try to find the PUSH1 0x80 PUSH1 0x40 (common start of runtime)
            runtime_start = bytecode.find('608060')
            if runtime_start > 0 and runtime_start % 2 == 0:
                return bytecode[runtime_start:]
            
            return None
        except Exception as e:
            logger.error(f"Error extracting runtime bytecode: {e}")
            return None
    
    def _post_process_storage_accesses(self) -> None:
        """
        Post-process storage accesses to identify patterns like mappings and arrays.
        This is called after symbolic execution is complete.
        """
        for access in self.storage_accesses:
            # Check for mapping patterns (keccak256 hash of key with slot)
            if not access.slot.concrete and isinstance(access.slot.value, z3.BitVecRef):
                slot_str = str(access.slot.value)
                if "keccak256" in slot_str:
                    access.is_mapping = True
                    logger.debug(f"Detected mapping access: {access}")
                    
                    # Try to extract base slot and key type
                    if hasattr(access.slot, 'keccak_args') and access.slot.keccak_args:
                        access.base_slot = access.slot.keccak_args.get('base_slot')
                        
                        # Try to infer key type from memory content
                        memory_content = access.slot.keccak_args.get('memory_content', [])
                        if memory_content:
                            # Simple heuristic: if first value looks like an address (20 bytes)
                            if any(val < (1 << 160) for val in memory_content):
                                access.key_type = "address"
                            else:
                                access.key_type = "uint256"
            
            # Check for array patterns (base slot + index)
            elif not access.slot.concrete and isinstance(access.slot.value, z3.BitVecRef):
                slot_str = str(access.slot.value)
                if "+" in slot_str and not "keccak256" in slot_str:
                    access.is_array = True
                    logger.debug(f"Detected array access: {access}")
                    
                    # Try to extract base slot
                    if hasattr(access.slot, 'storage_base'):
                        access.base_slot = access.slot.storage_base
    
    def _execute(self, operations: List[Tuple[str, int, Optional[bytes], int]], 
                state: ExecutionState, depth: int = 0) -> None:
        """Execute bytecode operations symbolically."""
        # Check execution depth
        if depth > self.max_depth:
            logger.debug(f"Reached maximum execution depth ({self.max_depth})")
            return
        
        # Check execution paths
        if self.execution_paths >= self.max_paths:
            logger.warning(f"Reached maximum number of execution paths ({self.max_paths})")
            return
        
        # Main execution loop
        while 0 <= state.pc < len(operations):
            # Get current operation
            opcode_name, opcode_value, push_data, offset = operations[state.pc]
            
            # Debug logging for important operations
            if opcode_value in (Opcode.SLOAD, Opcode.SSTORE, Opcode.SHA3):
                logger.debug(f"Executing {opcode_name} at PC {offset}")
            
            try:
                # Handle different categories of opcodes
                if Opcode.PUSH1 <= opcode_value <= Opcode.PUSH32:
                    self._handle_push(state, opcode_value, push_data)
                elif Opcode.DUP1 <= opcode_value <= Opcode.DUP16:
                    self._handle_dup(state, opcode_value)
                elif Opcode.SWAP1 <= opcode_value <= Opcode.SWAP16:
                    self._handle_swap(state, opcode_value)
                elif opcode_value in (Opcode.ADD, Opcode.SUB, Opcode.MUL, Opcode.DIV, Opcode.MOD):
                    self._handle_arithmetic(state, opcode_value)
                elif opcode_value in (Opcode.LT, Opcode.GT, Opcode.EQ, Opcode.ISZERO):
                    self._handle_comparison(state, opcode_value)
                elif opcode_value in (Opcode.AND, Opcode.OR, Opcode.XOR, Opcode.NOT):
                    self._handle_bitwise(state, opcode_value)
                elif opcode_value == Opcode.SHA3:
                    self._handle_sha3(state)
                elif opcode_value == Opcode.SLOAD:
                    self._handle_sload(state, offset)
                elif opcode_value == Opcode.SSTORE:
                    self._handle_sstore(state, offset)
                elif opcode_value in (Opcode.MLOAD, Opcode.MSTORE, Opcode.MSTORE8):
                    self._handle_memory(state, opcode_value)
                elif opcode_value == Opcode.JUMPI:
                    # Handle conditional jump - this is where path forking happens
                    new_paths = self._handle_jumpi(state, operations)
                    if new_paths:
                        for new_state in new_paths:
                            self.execution_paths += 1
                            if self.execution_paths < self.max_paths:
                                self._execute(operations, new_state, depth + 1)
                        # Current path continues with the false branch
                        state.pc += 1
                        continue
                elif opcode_value == Opcode.JUMP:
                    # Handle unconditional jump
                    if not self._handle_jump(state, operations):
                        # If jump fails, end this path
                        return
                    continue
                elif opcode_value in (Opcode.RETURN, Opcode.REVERT, Opcode.STOP, Opcode.SELFDESTRUCT):
                    # End of execution
                    return
                else:
                    # For other opcodes, handle based on stack effect
                    self._handle_generic_opcode(state, opcode_value)
                
                # Move to next instruction by default
                state.pc += 1
            
            except Exception as e:
                logger.error(f"Error executing {opcode_name} at PC {state.pc}: {e}")
                state.pc += 1
    
    def _handle_push(self, state: ExecutionState, opcode_value: int, push_data: Optional[bytes]) -> None:
        """Process a PUSH operation by pushing a value onto the stack."""
        if push_data:
            value = int.from_bytes(push_data, byteorder='big')
            state.push(SymbolicValue(value))
        else:
            # If push data is incomplete, use a symbolic value
            state.push(SymbolicValue())
    
    def _handle_dup(self, state: ExecutionState, opcode_value: int) -> None:
        """Process a DUP operation by duplicating a stack value."""
        position = opcode_value - Opcode.DUP1
        try:
            value = state.peek(position)
            state.push(value)
        except IndexError:
            # Stack underflow, use symbolic value
            state.push(SymbolicValue())
    
    def _handle_swap(self, state: ExecutionState, opcode_value: int) -> None:
        """Process a SWAP operation by exchanging stack values."""
        position = opcode_value - Opcode.SWAP1
        if len(state.stack) >= position + 2:
            # Need at least position+2 items on stack
            state.stack[-1], state.stack[-(position + 2)] = state.stack[-(position + 2)], state.stack[-1]
    
    def _handle_arithmetic(self, state: ExecutionState, opcode_value: int) -> None:
        """Process arithmetic operations (ADD, SUB, MUL, DIV, MOD)."""
        if len(state.stack) < 2:
            # Stack underflow, push symbolic value
            state.push(SymbolicValue())
            return
        
        b, a = state.pop(), state.pop()
        
        # If both values are concrete, compute the result
        if a.concrete and b.concrete:
            if opcode_value == Opcode.ADD:
                result = (a.value + b.value) & ((1 << 256) - 1)
            elif opcode_value == Opcode.SUB:
                result = (a.value - b.value) & ((1 << 256) - 1)
            elif opcode_value == Opcode.MUL:
                result = (a.value * b.value) & ((1 << 256) - 1)
            elif opcode_value == Opcode.DIV:
                result = 0 if b.value == 0 else a.value // b.value
            elif opcode_value == Opcode.MOD:
                result = 0 if b.value == 0 else a.value % b.value
            else:
                result = 0  # Should not happen
                
            state.push(SymbolicValue(result))
        else:
            # If either value is symbolic, create a new symbolic value
            result = SymbolicValue()
            
            # For storage analysis, track array index operations
            if opcode_value == Opcode.ADD:
                # Check for array access pattern (base + index)
                if a.concrete and a.value >= 0 and a.value < 100:  # Small constant might be an array base
                    result.is_array_index = True
                    result.storage_base = a.value
                elif b.concrete and b.value >= 0 and b.value < 100:
                    result.is_array_index = True
                    result.storage_base = b.value
            
            state.push(result)
    
    def _handle_comparison(self, state: ExecutionState, opcode_value: int) -> None:
        """Process comparison operations (LT, GT, EQ, ISZERO)."""
        if opcode_value == Opcode.ISZERO:
            if not state.stack:
                state.push(SymbolicValue())
                return
                
            a = state.pop()
            if a.concrete:
                state.push(SymbolicValue(1 if a.value == 0 else 0))
            else:
                state.push(SymbolicValue())
        else:
            if len(state.stack) < 2:
                state.push(SymbolicValue())
                return
                
            b, a = state.pop(), state.pop()
            if a.concrete and b.concrete:
                if opcode_value == Opcode.LT:
                    result = 1 if a.value < b.value else 0
                elif opcode_value == Opcode.GT:
                    result = 1 if a.value > b.value else 0
                elif opcode_value == Opcode.EQ:
                    result = 1 if a.value == b.value else 0
                else:
                    result = 0  # Should not happen
                    
                state.push(SymbolicValue(result))
            else:
                state.push(SymbolicValue())
    
    def _handle_bitwise(self, state: ExecutionState, opcode_value: int) -> None:
        """Process bitwise operations (AND, OR, XOR, NOT)."""
        if opcode_value == Opcode.NOT:
            if not state.stack:
                state.push(SymbolicValue())
                return
                
            a = state.pop()
            if a.concrete:
                state.push(SymbolicValue(((1 << 256) - 1) ^ a.value))
            else:
                state.push(SymbolicValue())
        else:
            if len(state.stack) < 2:
                state.push(SymbolicValue())
                return
                
            b, a = state.pop(), state.pop()
            if a.concrete and b.concrete:
                if opcode_value == Opcode.AND:
                    result = a.value & b.value
                elif opcode_value == Opcode.OR:
                    result = a.value | b.value
                elif opcode_value == Opcode.XOR:
                    result = a.value ^ b.value
                else:
                    result = 0  # Should not happen
                    
                state.push(SymbolicValue(result))
            else:
                state.push(SymbolicValue())
    
    def _handle_sha3(self, state: ExecutionState) -> None:
        """Process SHA3 (Keccak256) hashing operation."""
        if len(state.stack) < 2:
            state.push(SymbolicValue())
            return
            
        size, offset = state.pop(), state.pop()
        
        # Create a symbolic value for the hash result
        hash_value = SymbolicValue()
        hash_value.is_keccak = True
        
        # Try to extract memory content for better hash representation
        memory_content = []
        base_slot = None
        
        if offset.concrete and size.concrete:
            # Try to get actual memory content if available
            for i in range(offset.value, offset.value + size.value, 32):  # Process in 32-byte chunks
                if i in state.memory and state.memory[i].concrete:
                    memory_content.append(state.memory[i].value)
                    
                    # Check if this might be a storage slot (small constant)
                    if state.memory[i].value < 100:
                        base_slot = state.memory[i].value
            
            # Create a more descriptive symbolic value
            if memory_content:
                # If we have concrete memory content, use it to create a more specific hash
                hash_value.value = z3.BitVec(
                    f"keccak256({memory_content})", 
                    256
                )
            else:
                # Otherwise use the generic memory range
                hash_value.value = z3.BitVec(
                    f"keccak256(mem[{offset.value}:{offset.value + size.value}])", 
                    256
                )
            
            # Store metadata for mapping detection
            hash_value.keccak_args = {
                'offset': offset.value,
                'size': size.value,
                'memory_content': memory_content,
                'base_slot': base_slot
            }
        
        state.push(hash_value)
    
    def _handle_sload(self, state: ExecutionState, offset: int) -> None:
        """Process SLOAD operation with enhanced detection."""
        # Create a placeholder slot if stack is empty
        slot = state.pop() if state.stack else SymbolicValue()
        
        # Create a storage access record
        access = StorageAccess('SLOAD', slot, pc=offset)
        
        # Enhance detection for mappings and arrays
        if slot.is_keccak:
            access.is_mapping = True
            access.base_slot = slot.keccak_args.get('base_slot') if hasattr(slot, 'keccak_args') else None
            logger.debug(f"Detected mapping SLOAD at PC {offset}")
        elif slot.is_array_index:
            access.is_array = True
            access.base_slot = slot.storage_base
            logger.debug(f"Detected array SLOAD at PC {offset}")
        
        # Add the access to our list
        self.storage_accesses.append(access)
        logger.debug(f"Detected SLOAD at PC {offset} for slot {slot}")
        
        # Provide a value for the load operation
        if slot.concrete and slot.value in state.storage:
            state.push(state.storage[slot.value])
        else:
            # Create a new symbolic value for unknown storage
            state.push(SymbolicValue())
    
    def _handle_sstore(self, state: ExecutionState, offset: int) -> None:
        """Process SSTORE operation with enhanced detection."""
        # Create placeholders if stack is insufficient
        if len(state.stack) < 2:
            # Ensure we still record something even with incomplete stack
            slot = SymbolicValue()
            value = SymbolicValue()
            if state.stack:
                value = state.pop()
        else:
            value, slot = state.pop(), state.pop()
        
        # Create a storage access record
        access = StorageAccess('SSTORE', slot, value, pc=offset)
        
        # Enhance detection for mappings and arrays
        if slot.is_keccak:
            access.is_mapping = True
            access.base_slot = slot.keccak_args.get('base_slot') if hasattr(slot, 'keccak_args') else None
            logger.debug(f"Detected mapping SSTORE at PC {offset}")
        elif slot.is_array_index:
            access.is_array = True
            access.base_slot = slot.storage_base
            logger.debug(f"Detected array SSTORE at PC {offset}")
        
        # Add the access to our list
        self.storage_accesses.append(access)
        logger.debug(f"Detected SSTORE at PC {offset}: {slot} = {value}")
        
        # Update storage if we have a concrete slot
        if slot.concrete:
            state.storage[slot.value] = value
    
    def _handle_memory(self, state: ExecutionState, opcode_value: int) -> None:
        """Process memory operations (MLOAD, MSTORE, MSTORE8)."""
        if opcode_value == Opcode.MLOAD:
            if not state.stack:
                state.push(SymbolicValue())
                return
                
            offset = state.pop()
            if offset.concrete and offset.value in state.memory:
                state.push(state.memory[offset.value])
            else:
                state.push(SymbolicValue())
        
        elif opcode_value == Opcode.MSTORE:
            if len(state.stack) < 2:
                return
                
            value, offset = state.pop(), state.pop()
            if offset.concrete:
                state.memory[offset.value] = value
                
                # Track memory regions for keccak analysis
                # This helps with mapping key detection
                if offset.value % 32 == 0:  # Word-aligned
                    region_offset = offset.value
                    region_size = 32
                    region_values = [value]
                    state.store_memory_region(region_offset, region_size, region_values)
        
        elif opcode_value == Opcode.MSTORE8:
            if len(state.stack) < 2:
                return
                
            value, offset = state.pop(), state.pop()
            if offset.concrete:
                if value.concrete:
                    # Store only the lowest byte
                    byte_value = value.value & 0xFF
                    state.memory[offset.value] = SymbolicValue(byte_value)
                else:
                    state.memory[offset.value] = SymbolicValue()
    
    def _handle_jumpi(self, state: ExecutionState, 
                     operations: List[Tuple[str, int, Optional[bytes], int]]) -> List[ExecutionState]:
        """Process JUMPI (conditional jump) operation."""
        if len(state.stack) < 2:
            return []
            
        condition, dest = state.pop(), state.pop()
        
        # If condition is concrete, determine which path to take
        if condition.concrete:
            if condition.value:
                # True path - jump to destination
                if dest.concrete:
                    jump_dest = self._find_jump_dest(operations, dest.value)
                    if jump_dest is not None:
                        state.pc = jump_dest
                        return []  # No forking needed
            # False path continues to next instruction
            return []
        
        # Symbolic condition requires forking execution paths
        if not dest.concrete:
            return []  # Can't determine jump destination
        
        jump_dest = self._find_jump_dest(operations, dest.value)
        if jump_dest is None:
            return []  # Invalid jump destination
        
        # Create a new state for the true path
        true_state = state.clone()
        true_state.pc = jump_dest
        
        return [true_state]  # Return new state for forking
    
    def _handle_jump(self, state: ExecutionState, 
                    operations: List[Tuple[str, int, Optional[bytes], int]]) -> bool:
        """Process JUMP (unconditional jump) operation."""
        if not state.stack:
            return False
            
        dest = state.pop()
        if not dest.concrete:
            return False  # Can't determine jump destination
        
        jump_dest = self._find_jump_dest(operations, dest.value)
        if jump_dest is None:
            return False  # Invalid jump destination
        
        state.pc = jump_dest
        return True
    
    def _handle_generic_opcode(self, state: ExecutionState, opcode_value: int) -> None:
        """Process other opcodes based on their stack effect."""
        stack_in, stack_out = get_stack_effect(opcode_value)
        
        # Pop items from stack
        for _ in range(stack_in):
            if state.stack:
                state.pop()
        
        # Push symbolic values to stack
        for _ in range(stack_out):
            state.push(SymbolicValue())
    
    def _find_jump_dest(self, operations: List[Tuple[str, int, Optional[bytes], int]], 
                       dest_value: int) -> Optional[int]:
        """Find the index of a JUMPDEST operation."""
        for i, op in enumerate(operations):
            if op[0] == 'JUMPDEST' and op[3] == dest_value:
                return i
        return None
