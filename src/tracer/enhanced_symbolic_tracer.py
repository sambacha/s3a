"""
Enhanced symbolic execution engine for EVM bytecode analysis.

This module extends the base symbolic executor with evmole integration
to provide better path coverage and more efficient storage access detection.
"""

from typing import Dict, List, Optional, Set, Tuple, Union, Any, DefaultDict
import z3
import logging
from queue import PriorityQueue
import time

from .symbolic_tracer import (
    SymbolicExecutor,
    ExecutionState,
    StorageAccess,
    SymbolicValue,
)
from .evmole_integration import EvmoleWrapper, EVMOLE_AVAILABLE
from .evm_opcodes import Opcode, disassemble_bytecode

logger = logging.getLogger(__name__)


class EnhancedSymbolicExecutor(SymbolicExecutor):
    """
    Enhanced symbolic executor that uses evmole for better path coverage and efficiency.

    This executor extends the base SymbolicExecutor with:
    - Dynamic path limits based on contract complexity
    - Priority-based path exploration focused on storage operations
    - Path deduplication for more efficient analysis
    """

    def __init__(self, max_paths: int = 200, max_depth: int = 200):
        """
        Initialize the enhanced symbolic executor.

        Args:
            max_paths: Default maximum number of execution paths to explore
            max_depth: Maximum depth of execution
        """
        super().__init__(max_paths, max_depth)
        self.evmole = EvmoleWrapper()
        self.storage_accessing_blocks = set()
        self.function_entry_points = {}
        self.explored_paths = set()
        self.start_time = None
        self.time_limit = 60  # Default 60 second timeout

    def analyze(self, bytecode: str) -> List[StorageAccess]:
        """
        Analyze bytecode to identify storage access patterns with improved path coverage.

        Args:
            bytecode: Hexadecimal string representing the bytecode

        Returns:
            List of StorageAccess objects
        """
        # Start timer for analysis
        self.start_time = time.time()

        # Reset state
        self.storage_accesses = []
        self.execution_paths = 0
        self.storage_slots_accessed = set()
        self.potential_structs = {}
        self.explored_paths = set()

        # Validate bytecode
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        # Extract runtime bytecode if this is contract creation bytecode
        runtime_bytecode = self._extract_runtime_bytecode(bytecode)
        if runtime_bytecode:
            logger.info(
                f"Extracted runtime bytecode of size: {len(runtime_bytecode) // 2} bytes"
            )
            bytecode = runtime_bytecode

        # Run evmole analysis to guide symbolic execution (if available)
        logger.info("Running evmole analysis for guided symbolic execution...")
        evmole_data = self.evmole.get_control_flow_data(bytecode) or {}
        evmole_storage = self.evmole.get_storage_layout(bytecode) or []

        if not EVMOLE_AVAILABLE:
            logger.warning(
                "evmole not available, falling back to standard path exploration"
            )
        elif not evmole_data:
            logger.warning(
                "evmole analysis returned no data, falling back to standard path exploration"
            )

        # Identify blocks that access storage
        self._identify_storage_accessing_blocks(evmole_data, evmole_storage)

        # Extract function entry points
        if "function_blocks" in evmole_data:
            self.function_entry_points = {
                int(selector, 16)
                if selector.startswith("0x")
                else int(selector, 16): blocks[0] if blocks else None
                for selector, blocks in evmole_data.get("function_blocks", {}).items()
            }

        # Disassemble bytecode
        operations = disassemble_bytecode(bytecode)
        logger.info(f"Disassembled {len(operations)} operations from bytecode")

        # Identify function entry points (combine with evmole data)
        self._identify_function_entries(operations)

        # Calculate dynamic path limit based on contract complexity
        self.max_paths = self._calculate_dynamic_path_limit(operations, evmole_data)
        logger.info(f"Dynamic path limit set to {self.max_paths} paths")

        # Use priority-based path exploration
        logger.info("Starting priority-based symbolic execution...")
        self._execute_with_priorities(operations, evmole_data)

        # Post-process storage accesses to identify patterns
        self._post_process_storage_accesses()

        duration = time.time() - self.start_time
        logger.info(
            f"Analysis complete: {len(self.storage_accesses)} storage accesses, "
            f"{self.execution_paths} execution paths, "
            f"{duration:.2f} seconds"
        )

        return self.storage_accesses

    def _identify_function_entries(self, operations: List) -> None:
        """
        Identify potential function entry points in the bytecode.

        This method looks for patterns that indicate the start of functions,
        particularly examining JUMPDEST operations near the beginning of the contract.

        Args:
            operations: List of disassembled operations
        """
        # Always initialize function_entries as a new set
        self.function_entries = set()

        # Start by adding any function entries we found from evmole
        if hasattr(self, "function_entry_points"):
            for pc in self.function_entry_points.values():
                if pc is not None:
                    self.function_entries.add(pc)

        # Now look for JUMPDESTs that might be function entries
        for i, (opcode_name, opcode_value, _, offset) in enumerate(operations):
            # JUMPDEST operations are potential function entry points
            if opcode_name == "JUMPDEST":
                # Look for patterns that suggest a function entry
                # For example, a JUMPDEST followed by operations like PUSH1 0x80, PUSH1 0x40, etc.
                if i < len(operations) - 3:
                    # Simple heuristic: JUMPDEST followed by standard function prologue
                    if operations[i + 1][0].startswith("PUSH"):
                        self.function_entries.add(i)

        logger.info(
            f"Identified {len(self.function_entries)} potential function entries"
        )

    def _calculate_dynamic_path_limit(self, operations: List, evmole_data: Dict) -> int:
        """
        Calculate a dynamic path limit based on contract complexity.

        Args:
            operations: List of disassembled operations
            evmole_data: Control flow data from evmole

        Returns:
            Adjusted path limit
        """
        base_limit = 200  # Start with default

        # If no evmole data, use a simpler calculation based just on code size
        if not evmole_data:
            code_size_factor = len(operations) / 1000  # Normalize by 1000 instructions
            adjustment = code_size_factor * 0.5
            capped_adjustment = min(
                2.0, adjustment
            )  # Less aggressive without evmole data
            return int(base_limit * (1.0 + capped_adjustment))

        # With evmole data, use more sophisticated calculation
        # Adjust based on code size
        code_size_factor = len(operations) / 1000  # Normalize by 1000 instructions

        # Adjust based on number of blocks
        num_blocks = len(evmole_data.get("blocks", {}))
        blocks_factor = num_blocks / 50  # Normalize by 50 blocks

        # Adjust based on number of storage-accessing blocks
        storage_factor = (
            len(self.storage_accessing_blocks) / 10
        )  # Normalize by 10 storage blocks

        # Combine factors with different weights
        adjustment = (
            (code_size_factor * 0.3) + (blocks_factor * 0.5) + (storage_factor * 1.0)
        )

        # Cap the adjustment to avoid excessive paths
        capped_adjustment = min(5.0, adjustment)  # Maximum 5x increase

        return int(base_limit * (1.0 + capped_adjustment))

    def _identify_storage_accessing_blocks(
        self, evmole_data: Dict, evmole_storage: List
    ) -> None:
        """
        Identify which blocks are likely to access storage.

        Args:
            evmole_data: Control flow data from evmole
            evmole_storage: Storage layout data from evmole
        """
        # If we don't have evmole data, we can't identify storage-accessing blocks
        if not evmole_data or not evmole_storage:
            logger.warning("No evmole data available for storage block identification")
            return

        # Extract function selectors that access storage
        storage_functions = set()
        for record in evmole_storage:
            for selector in record.get("accessing_functions", {}).get("reads", []):
                storage_functions.add(selector)
            for selector in record.get("accessing_functions", {}).get("writes", []):
                storage_functions.add(selector)

        # Map functions to blocks
        function_blocks = evmole_data.get("function_blocks", {})
        for selector, blocks in function_blocks.items():
            if selector in storage_functions:
                self.storage_accessing_blocks.update(blocks)

        logger.info(
            f"Identified {len(self.storage_accessing_blocks)} blocks that access storage"
        )

    def _execute_with_priorities(self, operations: List, evmole_data: Dict) -> None:
        """
        Execute bytecode with prioritized path exploration.

        This method uses a priority queue to explore the most promising paths first,
        focusing on paths that are likely to access storage.

        Args:
            operations: List of disassembled operations
            evmole_data: Control flow data from evmole
        """
        # Create priority queue for states
        priority_queue = PriorityQueue()

        # Start with initial state
        initial_state = ExecutionState()
        initial_priority = self._calculate_state_priority(
            initial_state, operations, evmole_data
        )

        # Priority queue uses negative priority for highest-first ordering
        priority_queue.put((-initial_priority, 0, initial_state))

        # Track a counter for tiebreaking same-priority states
        counter = 1

        while not priority_queue.empty() and self.execution_paths < self.max_paths:
            # Check timeout
            if time.time() - self.start_time > self.time_limit:
                logger.warning(f"Execution time limit ({self.time_limit}s) reached")
                break

            # Get highest priority state
            neg_priority, _, current_state = priority_queue.get()
            priority = -neg_priority  # Convert back to positive

            # Skip already explored states (path deduplication)
            state_hash = self._hash_state(current_state)
            if state_hash in self.explored_paths:
                continue

            self.explored_paths.add(state_hash)

            # Track current function for context
            if (
                hasattr(self, "function_entries")
                and current_state.pc in self.function_entries
            ):
                self.current_function = current_state.pc
                # Track storage access count for this state if not already present
                if not hasattr(current_state, "storage_access_count"):
                    current_state.storage_access_count = 0

            # Debug logging
            if self.execution_paths % 50 == 0:
                logger.debug(
                    f"Exploring path {self.execution_paths} with priority {priority:.2f}"
                )

            # Process the current instruction
            try:
                opcode_name, opcode_value, push_data, offset = operations[
                    current_state.pc
                ]

                # Debug logging for important operations
                if opcode_value in (Opcode.SLOAD, Opcode.SSTORE, Opcode.SHA3):
                    logger.debug(f"Executing {opcode_name} at PC {offset}")

                # Handle different categories of opcodes
                if Opcode.PUSH1 <= opcode_value <= Opcode.PUSH32:
                    self._handle_push(current_state, opcode_value, push_data)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif Opcode.DUP1 <= opcode_value <= Opcode.DUP16:
                    self._handle_dup(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif Opcode.SWAP1 <= opcode_value <= Opcode.SWAP16:
                    self._handle_swap(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value in (
                    Opcode.ADD,
                    Opcode.SUB,
                    Opcode.MUL,
                    Opcode.DIV,
                    Opcode.MOD,
                ):
                    self._handle_arithmetic(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value in (Opcode.LT, Opcode.GT, Opcode.EQ, Opcode.ISZERO):
                    self._handle_comparison(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value in (Opcode.AND, Opcode.OR, Opcode.XOR, Opcode.NOT):
                    self._handle_bitwise(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value in (Opcode.SHL, Opcode.SHR, Opcode.SAR):
                    self._handle_shifts(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value == Opcode.SHA3:
                    self._handle_sha3(current_state)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value == Opcode.SLOAD:
                    self._handle_sload(current_state, offset)
                    current_state.pc += 1
                    # Track storage access
                    if not hasattr(current_state, "storage_access_count"):
                        current_state.storage_access_count = 0
                    current_state.storage_access_count += 1
                    current_state.last_storage_slot = (
                        current_state.storage_slot
                        if hasattr(current_state, "storage_slot")
                        else None
                    )
                    # Update priority after storage access
                    new_priority = self._calculate_state_priority(
                        current_state, operations, evmole_data
                    )
                    priority_queue.put((-new_priority, counter, current_state))
                    counter += 1
                elif opcode_value == Opcode.SSTORE:
                    self._handle_sstore(current_state, offset)
                    current_state.pc += 1
                    # Track storage access
                    if not hasattr(current_state, "storage_access_count"):
                        current_state.storage_access_count = 0
                    current_state.storage_access_count += 1
                    current_state.last_storage_slot = (
                        current_state.storage_slot
                        if hasattr(current_state, "storage_slot")
                        else None
                    )
                    # Update priority after storage access
                    new_priority = self._calculate_state_priority(
                        current_state, operations, evmole_data
                    )
                    priority_queue.put((-new_priority, counter, current_state))
                    counter += 1
                elif opcode_value in (Opcode.MLOAD, Opcode.MSTORE, Opcode.MSTORE8):
                    self._handle_memory(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1
                elif opcode_value == Opcode.JUMPI:
                    # Handle conditional jump - path forking
                    new_states = self._handle_jumpi(current_state, operations)

                    # Queue new states with priorities
                    for new_state in new_states:
                        new_priority = self._calculate_state_priority(
                            new_state, operations, evmole_data
                        )
                        priority_queue.put((-new_priority, counter, new_state))
                        counter += 1

                    # Normal path continues (already handled in _handle_jumpi if needed)
                elif opcode_value == Opcode.JUMP:
                    # Handle unconditional jump
                    if self._handle_jump(current_state, operations):
                        # If jump was successful, continue with updated state
                        new_priority = self._calculate_state_priority(
                            current_state, operations, evmole_data
                        )
                        priority_queue.put((-new_priority, counter, current_state))
                        counter += 1
                    # If jump failed, this path is terminated (don't queue)
                elif opcode_value in (
                    Opcode.RETURN,
                    Opcode.REVERT,
                    Opcode.STOP,
                    Opcode.SELFDESTRUCT,
                ):
                    # End of execution for this path, don't queue it again
                    pass
                else:
                    # Handle generic opcodes
                    self._handle_generic_opcode(current_state, opcode_value)
                    current_state.pc += 1
                    # Continue with the same state
                    priority_queue.put((-priority, counter, current_state))
                    counter += 1

            except Exception as e:
                logger.error(f"Error executing at PC {current_state.pc}: {e}")
                # Try to continue with next instruction
                current_state.pc += 1
                priority_queue.put((-priority, counter, current_state))
                counter += 1

            self.execution_paths += 1

    def _calculate_state_priority(
        self, state: ExecutionState, operations: List, evmole_data: Dict
    ) -> float:
        """
        Calculate a priority score for an execution state.

        Higher priority means the state is more likely to access storage.

        Args:
            state: The execution state to prioritize
            operations: List of disassembled operations
            evmole_data: Control flow data from evmole

        Returns:
            Priority score (higher is better)
        """
        priority = 0.0

        # Base priority factors

        # 1. Is this state in a block known to access storage?
        if evmole_data:
            current_block = self._find_containing_block(state.pc, evmole_data)
            if current_block in self.storage_accessing_blocks:
                priority += 100.0

        # 2. How close is this state to a storage operation?
        min_distance = self._calculate_distance_to_storage_op(state.pc, operations)
        if min_distance < float("inf"):
            priority += 50.0 / (1.0 + min_distance * 0.1)

        # 3. Has this state previously accessed storage?
        if hasattr(state, "storage_access_count"):
            priority += 75.0 * state.storage_access_count

        # 4. Is this a new or recently discovered storage slot?
        if hasattr(state, "last_storage_slot") and state.last_storage_slot is not None:
            slot_value = self._normalize_slot(state.last_storage_slot)
            if slot_value not in self.storage_slots_accessed:
                priority += 200.0

        # 5. Penalty for states with many conditions (to favor simpler paths)
        condition_penalty = len(state.path_conditions) * 2.0
        priority -= condition_penalty

        return priority

    def _find_containing_block(self, pc: int, evmole_data: Dict) -> Optional[int]:
        """
        Find the block containing the given program counter.

        Args:
            pc: Program counter to find
            evmole_data: Control flow data from evmole

        Returns:
            Block start PC or None if not found
        """
        for start, block_info in evmole_data.get("blocks", {}).items():
            if pc >= block_info["start"] and pc <= block_info["end"]:
                return start
        return None

    def _calculate_distance_to_storage_op(self, pc: int, operations: List) -> float:
        """
        Calculate the minimum instruction distance to a storage operation.

        Args:
            pc: Current program counter
            operations: List of disassembled operations

        Returns:
            Minimum distance to a storage operation (inf if none found)
        """
        min_distance = float("inf")

        # Look ahead in the code for storage operations (limit lookahead to avoid excessive computation)
        for i, (opcode_name, _, _, _) in enumerate(operations[pc : pc + 50]):
            if opcode_name in ("SLOAD", "SSTORE"):
                min_distance = min(min_distance, i)

        return min_distance

    def _hash_state(self, state: ExecutionState) -> int:
        """
        Create a hash of the execution state for path deduplication.

        Args:
            state: Execution state to hash

        Returns:
            Hash of the state
        """
        # Create a tuple of key state components
        state_components = (
            state.pc,
            tuple(str(c.value) for c in state.path_conditions),
        )

        # Return hash of the components
        return hash(state_components)

    def _normalize_slot(self, slot: SymbolicValue) -> Union[int, str]:
        """
        Normalize a storage slot for consistent comparison.

        Args:
            slot: Storage slot as a SymbolicValue

        Returns:
            Normalized representation (int for concrete, str for symbolic)
        """
        if slot.concrete:
            return slot.value
        else:
            return str(slot.value)
