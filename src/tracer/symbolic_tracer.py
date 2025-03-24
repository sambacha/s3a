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
        self.is_nested_mapping = False
        self.is_struct = False
        self.base_slot = None
        self.key_type = None
        self.mask = None        # For packed variables
        self.operations = []    # Stack operations leading to this access
        self.context = None     # Additional context information
        self.function_pc = None # Program counter of the function containing this access
    
    def __str__(self) -> str:
        if self.op_type == 'SLOAD':
            return f"{self.op_type} {self.slot} @ PC {self.pc}"
        else:
            return f"{self.op_type} {self.slot} = {self.value} @ PC {self.pc}"
    
    def __repr__(self) -> str:
        return self.__str__()
    
    def add_operation(self, op: str) -> None:
        """Add an operation to the history of operations for this access."""
        self.operations.append(op)
    
    def set_mask(self, mask: int) -> None:
        """Set a bitmask for this operation (for packed variables)."""
        self.mask = mask


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
        
        # Track recent operations for better context
        self.recent_ops: List[str] = []
        
        # Track bitwise operations for packed variable detection
        self.recent_mask = None
        self.recent_shift = None
    
    def clone(self) -> 'ExecutionState':
        """Create a deep copy of this execution state."""
        new_state = ExecutionState(self.pc)
        new_state.stack = self.stack.copy()
        new_state.memory = self.memory.copy()
        new_state.storage = self.storage.copy()
        new_state.path_conditions = self.path_conditions.copy()
        new_state.memory_regions = self.memory_regions.copy()
        new_state.recent_ops = self.recent_ops.copy()
        new_state.recent_mask = self.recent_mask
        new_state.recent_shift = self.recent_shift
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
    
    def add_operation(self, op: str) -> None:
        """Add an operation to the recent operations list."""
        self.recent_ops.append(op)
        # Keep only the last 10 operations
        if len(self.recent_ops) > 10:
            self.recent_ops = self.recent_ops[-10:]


class SymbolicExecutor:
    """Executes EVM bytecode symbolically to analyze behavior."""
    
    def __init__(self, max_paths: int = DEFAULT_MAX_PATHS, max_depth: int = DEFAULT_MAX_DEPTH):
        """Initialize the symbolic executor with execution bounds."""
        self.solver = z3.Solver()
        self.storage_accesses: List[StorageAccess] = []
        self.execution_paths = 0
        self.max_paths = max_paths
        self.max_depth = max_depth
        
        # Track function entry points for better context
        self.function_entries = {}  # Map of PC -> function signature
        self.current_function = None  # Current function being executed
        
        # Track storage access patterns
        self.storage_slots_accessed = set()  # Set of all accessed slots
        self.potential_structs = {}  # Map of consecutive slots that might be structs
    
    def analyze(self, bytecode: str) -> List[StorageAccess]:
        """Analyze bytecode to identify storage access patterns."""
        # Reset state
        self.storage_accesses = []
        self.execution_paths = 0
        self.storage_slots_accessed = set()
        self.potential_structs = {}
        
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
        
        # Identify function entry points
        self._identify_function_entries(operations)
        
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
    
    def _identify_function_entries(self, operations: List[Tuple[str, int, Optional[bytes], int]]) -> None:
        """
        Identify function entry points in the contract bytecode.
        
        This looks for function selector comparisons in the dispatcher.
        """
        # Reset function entries
        self.function_entries = {}
        
        # Loop through operations looking for PUSH4 (function selectors)
        for i, (opcode_name, opcode_value, push_data, offset) in enumerate(operations):
            if opcode_name == 'PUSH4' and push_data:
                # This could be a function selector
                selector = int.from_bytes(push_data, byteorder='big')
                
                # Look ahead for EQ and JUMPI pattern (dispatcher)
                if i + 2 < len(operations) and operations[i+1][0] == 'EQ' and operations[i+2][0] == 'JUMPI':
                    # Get the jump destination
                    if operations[i+2][2]:  # JUMPI push_data
                        jump_dest = int.from_bytes(operations[i+2][2], byteorder='big')
                        self.function_entries[jump_dest] = f"0x{selector:08x}"
                        logger.debug(f"Identified function entry at PC {jump_dest}: selector {self.function_entries[jump_dest]}")
    
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
        
        # Track masking operations for packed variables
        recent_mask = None
        recent_shift = None
        
        # Map of known storage slots
        known_slots = {}
        
        # Track recent operations for context
        recent_ops = []
        
        for i, (opcode_name, opcode_value, push_data, offset) in enumerate(operations):
            # Add to recent operations
            recent_ops.append(opcode_name)
            if len(recent_ops) > 10:
                recent_ops = recent_ops[-10:]
            
            # Handle PUSH operations to track concrete values
            if Opcode.PUSH1 <= opcode_value <= Opcode.PUSH32 and push_data:
                value = int.from_bytes(push_data, byteorder='big')
                stack.append(SymbolicValue(value))
                
                # If this is a small value (likely a storage slot), remember it
                if value < 100:
                    known_slots[i] = value
                
                # Check for mask patterns
                if value & (value + 1) == 0 and value != 0:  # Is a mask with continuous 1s
                    recent_mask = value
            
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
            
            # Handle bitwise operations
            elif opcode_value == Opcode.AND and len(stack) >= 2:
                # This could be a masking operation for packed variables
                b = stack.pop()
                a = stack.pop()
                
                if b.concrete and (b.value & (b.value + 1) == 0) and b.value != 0:
                    # This is a continuous bitmask (like 0xFF, 0xFFFF, etc.)
                    recent_mask = b.value
                elif a.concrete and (a.value & (a.value + 1) == 0) and a.value != 0:
                    recent_mask = a.value
                
                # Push result
                stack.append(SymbolicValue())
            
            # Handle shift operations
            elif (opcode_value == Opcode.SHL or opcode_value == Opcode.SHR) and len(stack) >= 2:
                # This could be a shift operation for packed variables
                b = stack.pop()
                a = stack.pop()
                
                if a.concrete:
                    shift_amount = a.value
                    if opcode_value == Opcode.SHL:
                        recent_shift = shift_amount
                    else:  # SHR
                        recent_shift = -shift_amount
                
                # Push result
                stack.append(SymbolicValue())
            
            # Handle SLOAD operations
            elif opcode_value == Opcode.SLOAD:
                if stack:
                    slot = stack.pop()
                    # Create a storage access record
                    access = StorageAccess('SLOAD', slot, pc=offset)
                    
                    # Add mask information for packed variables
                    if recent_mask is not None:
                        access.set_mask(recent_mask)
                    
                    # Add recent operations for context
                    access.operations = recent_ops.copy()
                    
                    # Try to determine function context
                    access.function_pc = self._find_current_function(offset, operations)
                    
                    accesses.append(access)
                    logger.debug(f"Direct analysis: SLOAD at PC {offset} for slot {slot}")
                    
                    # Push a symbolic value for the loaded value
                    stack.append(SymbolicValue())
                else:
                    stack.append(SymbolicValue())
                
                # Clear mask after SLOAD
                recent_mask = None
                recent_shift = None
            
            # Handle SSTORE operations
            elif opcode_value == Opcode.SSTORE:
                if len(stack) >= 2:
                    value, slot = stack.pop(), stack.pop()
                    # Create a storage access record
                    access = StorageAccess('SSTORE', slot, value, pc=offset)
                    
                    # Add mask information for packed variables
                    if recent_mask is not None:
                        access.set_mask(recent_mask)
                    
                    # Add recent operations for context
                    access.operations = recent_ops.copy()
                    
                    # Try to determine function context
                    access.function_pc = self._find_current_function(offset, operations)
                    
                    accesses.append(access)
                    logger.debug(f"Direct analysis: SSTORE at PC {offset}: {slot} = {value}")
                
                # Clear mask after SSTORE
                recent_mask = None
                recent_shift = None
                
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
                    
                    # Check for nested mappings
                    if slot_str.count("keccak256") > 1:
                        access.is_nested_mapping = True
                        logger.debug(f"Direct analysis: Detected nested mapping access: {access}")
                    else:
                        logger.debug(f"Direct analysis: Detected mapping access: {access}")
            
            # Check for potential struct slots (consecutive integer slots)
            elif access.slot.concrete:
                slot_value = access.slot.value
                self.storage_slots_accessed.add(slot_value)
                
                # Check for adjacent slots
                for adjacent in [slot_value - 1, slot_value + 1]:
                    if adjacent in self.storage_slots_accessed:
                        if slot_value not in self.potential_structs:
                            self.potential_structs[slot_value] = set()
                        self.potential_structs[slot_value].add(adjacent)
                        access.is_struct = True
                        logger.debug(f"Direct analysis: Detected potential struct at slot {slot_value}")
        
        return accesses
    
    def _find_current_function(self, pc: int, operations: List[Tuple[str, int, Optional[bytes], int]]) -> Optional[int]:
        """
        Try to determine which function contains the given program counter.
        
        Args:
            pc: Program counter to check
            operations: List of operations
            
        Returns:
            Function entry point PC or None if not found
        """
        # Find the closest JUMPDEST before pc
        closest_jumpdest = None
        
        for i, (opcode_name, opcode_value, push_data, offset) in enumerate(operations):
            if offset > pc:
                break
            
            if opcode_name == 'JUMPDEST':
                if offset in self.function_entries:
                    closest_jumpdest = offset
        
        return closest_jumpdest
    
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
                    
                    # Check for nested mappings
                    if slot_str.count("keccak256") > 1:
                        access.is_nested_mapping = True
                        logger.debug(f"Detected nested mapping access: {access}")
                    else:
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
            
            # Check for potential struct members (consecutive slots)
            elif access.slot.concrete:
                slot_value = access.slot.value
                if slot_value in self.potential_structs:
                    access.is_struct = True
                    logger.debug(f"Detected potential struct member at slot {slot_value}")
    
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
            
            # Track current function
            if offset in self.function_entries:
                self.current_function = offset
            
            # Record operation for context
            state.add_operation(opcode_name)
            
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
                elif opcode_value in (Opcode.SHL, Opcode.SHR, Opcode.SAR):
                    self._handle_shifts(state, opcode_value)
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
            
            # Check for mask patterns (continuous bits)
            if value & (value + 1) == 0 and value != 0:  # Is a mask with continuous 1s
                state.recent_mask = value
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
                state.push(SymbolicValue(result))
            elif opcode_value == Opcode.SUB:
                result = (a.value - b.value) & ((1 << 256) - 1)
                state.push(SymbolicValue(result))
            elif opcode_value == Opcode.MUL:
                result = (a.value * b.value) & ((1 << 256) - 1)
                state.push(SymbolicValue(result))
            elif opcode_value == Opcode.DIV:
                if b.value == 0:
                    state.push(SymbolicValue(0))
                else:
                    result = a.value // b.value
                    state.push(SymbolicValue(result))
            elif opcode_value == Opcode.MOD:
                if b.value == 0:
                    state.push(SymbolicValue(0))
                else:
                    result = a.value % b.value
                    state.push(SymbolicValue(result))
        else:
            # For symbolic values, create a symbolic expression
            if opcode_value == Opcode.ADD:
                if a.concrete and a.value == 0:
                    state.push(b)
                elif b.concrete and b.value == 0:
                    state.push(a)
                else:
                    result = SymbolicValue()
                    if a.concrete and b.concrete:
                        # Both are concrete, should have been handled above
                        result.value = (a.value + b.value) & ((1 << 256) - 1)
                        result.concrete = True
                    elif a.is_symbolic and b.is_symbolic:
                        # Both symbolic, use Z3 expression
                        result.value = z3.simplify(a.value + b.value)
                    elif a.is_symbolic:
                        # a is symbolic, b is concrete
                        result.value = z3.simplify(a.value + b.value)
                    else:
                        # a is concrete, b is symbolic
                        result.value = z3.simplify(a.value + b.value)
                    state.push(result)
            elif opcode_value == Opcode.SUB:
                result = SymbolicValue()
                if a.concrete and b.concrete:
                    # Both are concrete, should have been handled above
                    result.value = (a.value - b.value) & ((1 << 256) - 1)
                    result.concrete = True
                else:
                    # Create a symbolic subtraction
                    result.value = z3.simplify(a.value - b.value if hasattr(a.value, '__sub__') else a.value)
                state.push(result)
            elif opcode_value == Opcode.MUL:
                if (a.concrete and a.value == 0) or (b.concrete and b.value == 0):
                    state.push(SymbolicValue(0))
                elif a.concrete and a.value == 1:
                    state.push(b)
                elif b.concrete and b.value == 1:
                    state.push(a)
                else:
                    result = SymbolicValue()
                    if a.concrete and b.concrete:
                        # Both are concrete, should have been handled above
                        result.value = (a.value * b.value) & ((1 << 256) - 1)
                        result.concrete = True
                    else:
                        # Create a symbolic multiplication
                        result.value = z3.simplify(a.value * b.value if hasattr(a.value, '__mul__') else a.value)
                    state.push(result)
            elif opcode_value == Opcode.DIV:
                if b.concrete and b.value == 0:
                    # Division by zero
                    state.push(SymbolicValue(0))
                elif a.concrete and a.value == 0:
                    # Zero divided by anything is zero
                    state.push(SymbolicValue(0))
                elif b.concrete and b.value == 1:
                    # Divide by one is identity
                    state.push(a)
                else:
                    result = SymbolicValue()
                    if a.concrete and b.concrete:
                        # Both are concrete, should have been handled above
                        result.value = a.value // b.value
                        result.concrete = True
                    else:
                        # Division with symbolic values is complex, use a new symbolic value
                        result.value = z3.simplify(z3.UDiv(a.value, b.value) if hasattr(a.value, '__truediv__') else a.value)
                    state.push(result)
            elif opcode_value == Opcode.MOD:
                if b.concrete and b.value == 0:
                    # Mod by zero is zero
                    state.push(SymbolicValue(0))
                elif a.concrete and a.value == 0:
                    # Zero mod anything is zero
                    state.push(SymbolicValue(0))
                else:
                    result = SymbolicValue()
                    if a.concrete and b.concrete:
                        # Both are concrete, should have been handled above
                        result.value = a.value % b.value
                        result.concrete = True
                    else:
                        # Mod with symbolic values, use a new symbolic value
                        result.value = z3.simplify(z3.URem(a.value, b.value) if hasattr(a.value, '__mod__') else a.value)
                    state.push(result)

    def _handle_comparison(self, state: ExecutionState, opcode_value: int) -> None:
        """Process comparison operations (LT, GT, EQ, ISZERO)."""
        if opcode_value == Opcode.ISZERO:
            if len(state.stack) < 1:
                state.push(SymbolicValue())
                return
            
            a = state.pop()
            
            if a.concrete:
                result = 1 if a.value == 0 else 0
                state.push(SymbolicValue(result))
            else:
                # Symbolic comparison with zero
                result = SymbolicValue()
                result.value = z3.simplify(a.value == 0)
                state.push(result)
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
                    result = 0  # Default for unknown comparison
                state.push(SymbolicValue(result))
            else:
                # Create symbolic comparison
                result = SymbolicValue()
                if opcode_value == Opcode.LT:
                    result.value = z3.simplify(z3.ULT(a.value, b.value))
                elif opcode_value == Opcode.GT:
                    result.value = z3.simplify(z3.UGT(a.value, b.value))
                elif opcode_value == Opcode.EQ:
                    result.value = z3.simplify(a.value == b.value)
                else:
                    # Unknown comparison, use symbolic value
                    pass
                state.push(result)

    def _handle_bitwise(self, state: ExecutionState, opcode_value: int) -> None:
        """Process bitwise operations (AND, OR, XOR, NOT)."""
        if opcode_value == Opcode.NOT:
            if len(state.stack) < 1:
                state.push(SymbolicValue())
                return
            
            a = state.pop()
            
            if a.concrete:
                result = ((1 << 256) - 1) ^ a.value
                state.push(SymbolicValue(result))
            else:
                # Symbolic bitwise NOT
                result = SymbolicValue()
                result.value = z3.simplify(~a.value)
                state.push(result)
        else:
            if len(state.stack) < 2:
                state.push(SymbolicValue())
                return
            
            b, a = state.pop(), state.pop()
            
            # Track if this is a masking operation for packed variables
            if opcode_value == Opcode.AND:
                if b.concrete and (b.value & (b.value + 1) == 0) and b.value != 0:
                    # This is a continuous bitmask (like 0xFF, 0xFFFF, etc.)
                    state.recent_mask = b.value
                elif a.concrete and (a.value & (a.value + 1) == 0) and a.value != 0:
                    state.recent_mask = a.value
            
            if a.concrete and b.concrete:
                if opcode_value == Opcode.AND:
                    result = a.value & b.value
                elif opcode_value == Opcode.OR:
                    result = a.value | b.value
                elif opcode_value == Opcode.XOR:
                    result = a.value ^ b.value
                else:
                    result = 0  # Default for unknown bitwise op
                state.push(SymbolicValue(result))
            else:
                # Create symbolic bitwise operation
                result = SymbolicValue()
                if opcode_value == Opcode.AND:
                    if a.concrete and a.value == 0:
                        # AND with 0 is always 0
                        result.concrete = True
                        result.value = 0
                    elif b.concrete and b.value == 0:
                        # AND with 0 is always 0
                        result.concrete = True
                        result.value = 0
                    elif a.concrete and a.value == ((1 << 256) - 1):
                        # AND with all 1s is identity
                        state.push(b)
                        return
                    elif b.concrete and b.value == ((1 << 256) - 1):
                        # AND with all 1s is identity
                        state.push(a)
                        return
                    else:
                        result.value = z3.simplify(a.value & b.value)
                elif opcode_value == Opcode.OR:
                    if a.concrete and a.value == 0:
                        # OR with 0 is identity
                        state.push(b)
                        return
                    elif b.concrete and b.value == 0:
                        # OR with 0 is identity
                        state.push(a)
                        return
                    elif a.concrete and a.value == ((1 << 256) - 1):
                        # OR with all 1s is all 1s
                        result.concrete = True
                        result.value = ((1 << 256) - 1)
                    elif b.concrete and b.value == ((1 << 256) - 1):
                        # OR with all 1s is all 1s
                        result.concrete = True
                        result.value = ((1 << 256) - 1)
                    else:
                        result.value = z3.simplify(a.value | b.value)
                elif opcode_value == Opcode.XOR:
                    if a.concrete and a.value == 0:
                        # XOR with 0 is identity
                        state.push(b)
                        return
                    elif b.concrete and b.value == 0:
                        # XOR with 0 is identity
                        state.push(a)
                        return
                    else:
                        result.value = z3.simplify(a.value ^ b.value)
                state.push(result)

    def _handle_shifts(self, state: ExecutionState, opcode_value: int) -> None:
        """Process shift operations (SHL, SHR, SAR)."""
        if len(state.stack) < 2:
            state.push(SymbolicValue())
            return
        
        b, a = state.pop(), state.pop()
        
        # Track shift operations for packed variables
        if a.concrete:
            shift_amount = a.value
            if opcode_value == Opcode.SHL:
                state.recent_shift = shift_amount
            elif opcode_value == Opcode.SHR:
                state.recent_shift = -shift_amount
        
        if a.concrete and b.concrete:
            if opcode_value == Opcode.SHL:
                # Left shift (SHL): shift a left by b bits
                if a.value >= 256:
                    # Shift by 256 or more results in 0
                    result = 0
                else:
                    result = (b.value << a.value) & ((1 << 256) - 1)
            elif opcode_value == Opcode.SHR:
                # Logical right shift (SHR): shift b right by a bits (unsigned)
                if a.value >= 256:
                    # Shift by 256 or more results in 0
                    result = 0
                else:
                    result = b.value >> a.value
            elif opcode_value == Opcode.SAR:
                # Arithmetic right shift (SAR): shift b right by a bits (signed)
                if a.value >= 256:
                    # For arithmetic shift, if b is negative, result is -1, otherwise 0
                    result = ((1 << 256) - 1) if b.value & (1 << 255) else 0
                else:
                    # Implement signed right shift
                    if b.value & (1 << 255):  # Check if b is negative (in 2's complement)
                        # For negative numbers, shift and fill with 1s
                        mask = ((1 << 256) - 1) ^ ((1 << (256 - a.value)) - 1)
                        result = (b.value >> a.value) | mask
                    else:
                        # For positive numbers, just do normal right shift
                        result = b.value >> a.value
            else:
                result = 0  # Default for unknown shift
            state.push(SymbolicValue(result))
        else:
            # Create symbolic shift operation
            result = SymbolicValue()
            if opcode_value == Opcode.SHL:
                if a.concrete and a.value >= 256:
                    # Shift by 256 or more results in 0
                    result.concrete = True
                    result.value = 0
                elif a.concrete and a.value == 0:
                    # Shift by 0 is identity
                    state.push(b)
                    return
                elif b.concrete and b.value == 0:
                    # Shifting 0 results in 0
                    result.concrete = True
                    result.value = 0
                else:
                    result.value = z3.simplify(z3.LShR(b.value, a.value))
            elif opcode_value == Opcode.SHR:
                if a.concrete and a.value >= 256:
                    # Shift by 256 or more results in 0
                    result.concrete = True
                    result.value = 0
                elif a.concrete and a.value == 0:
                    # Shift by 0 is identity
                    state.push(b)
                    return
                elif b.concrete and b.value == 0:
                    # Shifting 0 results in 0
                    result.concrete = True
                    result.value = 0
                else:
                    result.value = z3.simplify(z3.LShR(b.value, a.value))
            elif opcode_value == Opcode.SAR:
                if a.concrete and a.value >= 256:
                    # For arithmetic shift, handle large shifts symbolically
                    if b.concrete:
                        result.concrete = True
                        result.value = ((1 << 256) - 1) if b.value & (1 << 255) else 0
                    else:
                        # Try to create a conditional based on the sign bit
                        sign_bit = z3.simplify(z3.Extract(255, 255, b.value))
                        result.value = z3.simplify(z3.If(sign_bit == 1, ((1 << 256) - 1), 0))
                elif a.concrete and a.value == 0:
                    # Shift by 0 is identity
                    state.push(b)
                    return
                else:
                    # Use Z3's arithmetic right shift
                    result.value = z3.simplify(b.value >> a.value)
            state.push(result)

    def _handle_sha3(self, state: ExecutionState, offset: Optional[int] = None) -> None:
        """Process SHA3 operation (Keccak256 hash)."""
        if len(state.stack) < 2:
            state.push(SymbolicValue())
            return
        
        size, offset = state.pop(), state.pop()
        
        # Create a symbolic value for the hash result
        result = SymbolicValue()
        result.is_keccak = True
        
        # Try to extract memory content for the hash
        memory_content = []
        if offset.concrete and size.concrete:
            offset_val = offset.value
            size_val = size.value
            
            # If reasonable size (avoid huge memory dumps)
            if 0 <= size_val <= 1024:
                # Collect memory values
                for i in range(offset_val, offset_val + size_val, 32):
                    if i in state.memory:
                        memory_content.append(state.memory[i])
            
            # Store this memory region for later analysis
            if memory_content:
                state.store_memory_region(offset_val, size_val, memory_content)
        
        # Store metadata about this keccak hash for later analysis
        result.keccak_args = {
            'offset': offset,
            'size': size,
            'memory_content': memory_content
        }
        
        # Mark this as a potential storage key
        result.is_storage_key = True
        
        # Push the hash result onto the stack
        state.push(result)

    def _handle_sload(self, state: ExecutionState, pc: int) -> None:
        """Process SLOAD operation (load from storage)."""
        if len(state.stack) < 1:
            state.push(SymbolicValue())
            return
        
        slot = state.pop()
        
        # Create a storage access record
        access = StorageAccess('SLOAD', slot, pc=pc)
        
        # Add mask information for packed variables
        if state.recent_mask is not None:
            access.set_mask(state.recent_mask)
        
        # Add recent operations for context
        access.operations = state.recent_ops.copy()
        
        # Try to determine function context
        access.function_pc = self.current_function
        
        # Add to the list of storage accesses
        self.storage_accesses.append(access)
        
        # Get the value from storage or create a symbolic value
        if slot.concrete:
            slot_value = slot.value
            self.storage_slots_accessed.add(slot_value)
            
            # Check for adjacent slots for structs
            for adjacent in [slot_value - 1, slot_value + 1]:
                if adjacent in self.storage_slots_accessed:
                    if slot_value not in self.potential_structs:
                        self.potential_structs[slot_value] = set()
                    self.potential_structs[slot_value].add(adjacent)
                    access.is_struct = True
            
            if slot_value in state.storage:
                state.push(state.storage[slot_value])
            else:
                value = SymbolicValue()
                state.storage[slot_value] = value
                state.push(value)
        else:
            # For symbolic slots, create a symbolic value
            # This might be a mapping or array access
            slot_str = str(slot.value)
            
            # Check for mapping pattern (keccak256)
            if slot.is_keccak:
                access.is_mapping = True
                logger.debug(f"Detected mapping access at PC {pc}")
                
                # If we have the keccak args, try to determine key type
                if hasattr(slot, 'keccak_args') and slot.keccak_args:
                    memory_content = slot.keccak_args.get('memory_content', [])
                    if memory_content:
                        # Simple heuristic: if first value looks like an address (20 bytes)
                        if any(val.concrete and val.value < (1 << 160) for val in memory_content):
                            access.key_type = "address"
                        else:
                            access.key_type = "uint256"
            
            # Check for array pattern (base + index)
            elif "+" in slot_str:
                access.is_array = True
                logger.debug(f"Detected array access at PC {pc}")
                
                # Try to extract base slot
                if hasattr(slot, 'storage_base'):
                    access.base_slot = slot.storage_base
            
            # Create a symbolic value for the loaded value
            value = SymbolicValue()
            state.push(value)
        
        # Clear mask after SLOAD
        state.recent_mask = None
        state.recent_shift = None

    def _handle_sstore(self, state: ExecutionState, pc: int) -> None:
        """Process SSTORE operation (store to storage)."""
        if len(state.stack) < 2:
            return
        
        value, slot = state.pop(), state.pop()
        
        # Create a storage access record
        access = StorageAccess('SSTORE', slot, value, pc=pc)
        
        # Add mask information for packed variables
        if state.recent_mask is not None:
            access.set_mask(state.recent_mask)
        
        # Add recent operations for context
        access.operations = state.recent_ops.copy()
        
        # Try to determine function context
        access.function_pc = self.current_function
        
        # Add to the list of storage accesses
        self.storage_accesses.append(access)
        
        # Update storage state
        if slot.concrete:
            slot_value = slot.value
            self.storage_slots_accessed.add(slot_value)
            
            # Check for adjacent slots for structs
            for adjacent in [slot_value - 1, slot_value + 1]:
                if adjacent in self.storage_slots_accessed:
                    if slot_value not in self.potential_structs:
                        self.potential_structs[slot_value] = set()
                    self.potential_structs[slot_value].add(adjacent)
                    access.is_struct = True
            
            # Store the value
            state.storage[slot_value] = value
        else:
            # For symbolic slots, this might be a mapping or array access
            slot_str = str(slot.value)
            
            # Check for mapping pattern (keccak256)
            if slot.is_keccak:
                access.is_mapping = True
                logger.debug(f"Detected mapping SSTORE at PC {pc}")
                
                # If we have the keccak args, try to determine key type
                if hasattr(slot, 'keccak_args') and slot.keccak_args:
                    memory_content = slot.keccak_args.get('memory_content', [])
                    if memory_content:
                        # Simple heuristic: if first value looks like an address (20 bytes)
                        if any(val.concrete and val.value < (1 << 160) for val in memory_content):
                            access.key_type = "address"
                        else:
                            access.key_type = "uint256"
            
            # Check for array pattern (base + index)
            elif "+" in slot_str:
                access.is_array = True
                logger.debug(f"Detected array SSTORE at PC {pc}")
                
                # Try to extract base slot
                if hasattr(slot, 'storage_base'):
                    access.base_slot = slot.storage_base
        
        # Clear mask after SSTORE
        state.recent_mask = None
        state.recent_shift = None

    def _handle_memory(self, state: ExecutionState, opcode_value: int) -> None:
        """Process memory operations (MLOAD, MSTORE, MSTORE8)."""
        if opcode_value == Opcode.MLOAD:
            if len(state.stack) < 1:
                state.push(SymbolicValue())
                return
            
            offset = state.pop()
            
            if offset.concrete:
                offset_val = offset.value
                if offset_val in state.memory:
                    state.push(state.memory[offset_val])
                else:
                    value = SymbolicValue()
                    state.memory[offset_val] = value
                    state.push(value)
            else:
                # For symbolic offsets, create a symbolic value
                state.push(SymbolicValue())
        
        elif opcode_value == Opcode.MSTORE:
            if len(state.stack) < 2:
                return
            
            value, offset = state.pop(), state.pop()
            
            if offset.concrete:
                offset_val = offset.value
                state.memory[offset_val] = value
            
        elif opcode_value == Opcode.MSTORE8:
            if len(state.stack) < 2:
                return
            
            value, offset = state.pop(), state.pop()
            
            if offset.concrete and value.concrete:
                offset_val = offset.value
                # Store only the lowest byte
                byte_val = value.value & 0xFF
                state.memory[offset_val] = SymbolicValue(byte_val)
            elif offset.concrete:
                offset_val = offset.value
                # For symbolic values, create a symbolic byte
                state.memory[offset_val] = SymbolicValue()

    def _handle_jumpi(self, state: ExecutionState, operations: List[Tuple[str, int, Optional[bytes], int]]) -> List[ExecutionState]:
        """
        Process JUMPI operation (conditional jump).
        
        Returns:
            List of new execution states (for taken branches)
        """
        if len(state.stack) < 2:
            return []
        
        dest, cond = state.pop(), state.pop()
        
        # If condition is symbolic or non-zero, we need to fork execution
        if not cond.concrete or cond.value != 0:
            if dest.concrete:
                dest_val = dest.value
                # Find the JUMPDEST
                jumpdest_found = False
                for _, op_value, _, offset in operations:
                    if offset == dest_val and op_value == Opcode.JUMPDEST:
                        jumpdest_found = True
                        break
                
                if jumpdest_found:
                    # Create a new execution state for the taken branch
                    new_state = state.clone()
                    new_state.pc = dest_val
                    
                    # For symbolic conditions, add path constraint
                    if not cond.concrete:
                        new_state.path_conditions.append(cond.value != 0)
                    
                    return [new_state]
        
        # For concrete condition with value 0, just continue to next instruction
        if cond.concrete and cond.value == 0:
            return []
        
        # If we reach here, either:
        # 1. The destination is symbolic (we can't resolve it)
        # 2. No valid JUMPDEST was found
        # 3. Condition is symbolic and we're continuing with the false branch
        return []

    def _handle_jump(self, state: ExecutionState, operations: List[Tuple[str, int, Optional[bytes], int]]) -> bool:
        """
        Process JUMP operation (unconditional jump).
        
        Returns:
            True if jump was successful, False otherwise
        """
        if len(state.stack) < 1:
            return False
        
        dest = state.pop()
        
        if dest.concrete:
            dest_val = dest.value
            # Find the JUMPDEST
            for _, op_value, _, offset in operations:
                if offset == dest_val and op_value == Opcode.JUMPDEST:
                    state.pc = dest_val
                    return True
            
            # If no valid JUMPDEST found, end this path
            logger.debug(f"Invalid jump destination: {dest_val}")
            return False
        else:
            # If destination is symbolic, we can't resolve it
            logger.debug("Symbolic jump destination, ending path")
            return False

    def _handle_generic_opcode(self, state: ExecutionState, opcode_value: int) -> None:
        """Handle generic opcodes based on their stack effect."""
        stack_in, stack_out = get_stack_effect(opcode_value)
        
        # Pop input values
        args = []
        for _ in range(min(stack_in, len(state.stack))):
            args.append(state.pop())
        
        # If not enough values on stack, add symbolic values
        for _ in range(max(0, stack_in - len(args))):
            args.append(SymbolicValue())
        
        # Push output values (symbolic)
        for _ in range(stack_out):
            state.push(SymbolicValue())
