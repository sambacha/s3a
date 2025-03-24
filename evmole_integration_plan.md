# Integration Plan: Enhancing Z3 SMT Analyzer with evmole

This document outlines a comprehensive implementation plan for integrating the evmole decompiler with our existing Z3 SMT Storage Layout Analyzer. This integration will specifically address three critical issues: limited path coverage, inefficient symbolic execution, and inaccurate type inference.

## 1. Overview

### Current Limitations

Our Z3 SMT analyzer has three key limitations:

1. **Limited Path Coverage**: The tool has an arbitrary maximum execution path limit (DEFAULT_MAX_PATHS = 200), which may miss important storage access patterns in complex contracts.

2. **Inefficient Symbolic Execution**: The current symbolic execution engine does not prioritize paths that lead to storage accesses, wasting computational resources.

3. **Inaccurate Type Inference**: The type inference mechanism relies on simple heuristics that may misidentify variable types, especially for complex or custom types.

### evmole Capabilities

evmole provides several features that can directly address these limitations:

1. **Storage Layout Extraction**: Directly identifies storage slots, types, and which functions read/write to them.
2. **Control Flow Graph Analysis**: Provides detailed information about execution paths and their relationships.
3. **Function Identification**: Maps function selectors to code locations and identifies state mutability.
4. **Basic Block Analysis**: Breaks code into logical units for more efficient analysis.

### Integration Approach

We will implement a hybrid analysis system that:

1. Uses evmole's static analysis to guide our symbolic execution
2. Cross-validates storage layouts between both tools
3. Combines type information from static and dynamic analysis
4. Prioritizes execution paths based on evmole's insights

## 2. Technical Implementation

### 2.1 Initial Integration

First, we need to add evmole as a dependency and create a wrapper module:

```python
# src/tracer/evmole_integration.py
import evmole
from typing import Dict, List, Optional, Any, Union

class EvmoleWrapper:
    """Wrapper for evmole functionality to integrate with our analyzer."""
    
    def __init__(self):
        self.last_analysis = None
    
    def analyze_bytecode(self, bytecode: Union[bytes, str]) -> Any:
        """Run a complete evmole analysis on the provided bytecode."""
        self.last_analysis = evmole.contract_info(
            bytecode,
            selectors=True,
            arguments=True,
            state_mutability=True,
            storage=True,
            control_flow_graph=True,
            basic_blocks=True
        )
        return self.last_analysis
    
    def get_storage_layout(self, bytecode: Union[bytes, str]) -> List[Dict[str, Any]]:
        """Extract storage layout information from bytecode."""
        analysis = self.analyze_bytecode(bytecode)
        if not analysis.storage:
            return []
            
        result = []
        for record in analysis.storage:
            storage_item = {
                'slot': record.slot,
                'offset': record.offset,
                'type': record.type,
                'accessing_functions': {
                    'reads': record.reads,
                    'writes': record.writes
                }
            }
            result.append(storage_item)
            
        return result
    
    def get_control_flow_data(self, bytecode: Union[bytes, str]) -> Dict[str, Any]:
        """Extract control flow information to guide path exploration."""
        analysis = self.analyze_bytecode(bytecode)
        if not analysis.control_flow_graph:
            return {}
            
        # Map blocks by their starting offset
        blocks_by_start = {}
        for block in analysis.control_flow_graph.blocks:
            blocks_by_start[block.start] = {
                'start': block.start,
                'end': block.end,
                'type': self._get_block_type_info(block.btype)
            }
            
        # Create function -> blocks mapping
        function_blocks = {}
        if analysis.functions:
            for func in analysis.functions:
                function_blocks[func.selector] = self._find_blocks_for_function(
                    func.bytecode_offset, blocks_by_start)
        
        return {
            'blocks': blocks_by_start,
            'function_blocks': function_blocks
        }
    
    def _get_block_type_info(self, btype) -> Dict[str, Any]:
        """Convert block type to dictionary representation."""
        if isinstance(btype, evmole.BlockType.Terminate):
            return {'type': 'terminate', 'success': btype.success}
        elif isinstance(btype, evmole.BlockType.Jump):
            return {'type': 'jump', 'to': btype.to}
        elif isinstance(btype, evmole.BlockType.Jumpi):
            return {'type': 'jumpi', 'true_to': btype.true_to, 'false_to': btype.false_to}
        elif isinstance(btype, evmole.BlockType.DynamicJump):
            return {'type': 'dynamic_jump', 'to': [self._format_dynamic_jump(d) for d in btype.to]}
        elif isinstance(btype, evmole.BlockType.DynamicJumpi):
            return {
                'type': 'dynamic_jumpi', 
                'true_to': [self._format_dynamic_jump(d) for d in btype.true_to],
                'false_to': btype.false_to
            }
        return {'type': 'unknown'}
    
    def _format_dynamic_jump(self, jump) -> Dict[str, Any]:
        """Format dynamic jump information."""
        return {'path': jump.path, 'to': jump.to}
    
    def _find_blocks_for_function(self, offset: int, blocks_by_start: Dict[int, Dict]) -> List[int]:
        """Find blocks that belong to a function starting at the given offset."""
        # Simple implementation - we'd need more sophisticated analysis for complete accuracy
        result = []
        for start, block in blocks_by_start.items():
            if start >= offset:
                result.append(start)
        return result
```

### 2.2 Addressing Limited Path Coverage

To improve path coverage, we'll modify our symbolic execution engine to use evmole's control flow information:

```python
# In src/tracer/symbolic_tracer.py
from .evmole_integration import EvmoleWrapper

class EnhancedSymbolicExecutor(SymbolicExecutor):
    """Enhanced symbolic executor that uses evmole for better path coverage."""
    
    def __init__(self, max_paths: int = DEFAULT_MAX_PATHS, max_depth: int = DEFAULT_MAX_DEPTH):
        super().__init__(max_paths, max_depth)
        self.evmole = EvmoleWrapper()
        self.storage_accessing_blocks = set()
        self.function_entry_points = {}
        self.explored_paths = set()
        
    def analyze(self, bytecode: str) -> List[StorageAccess]:
        """Analyze bytecode with enhanced path coverage using evmole."""
        # Reset state
        self.storage_accesses = []
        self.execution_paths = 0
        self.storage_slots_accessed = set()
        self.potential_structs = {}
        self.explored_paths = set()
        
        # Run evmole analysis first
        evmole_data = self.evmole.get_control_flow_data(bytecode)
        evmole_storage = self.evmole.get_storage_layout(bytecode)
        
        # Identify blocks that access storage
        self._identify_storage_accessing_blocks(evmole_data, evmole_storage)
        
        # Extract function entry points
        if 'function_blocks' in evmole_data:
            self.function_entry_points = {
                int(selector, 16): blocks[0] if blocks else None
                for selector, blocks in evmole_data.get('function_blocks', {}).items()
            }
        
        # Disassemble bytecode
        operations = disassemble_bytecode(bytecode)
        
        # Calculate dynamic path limit based on contract complexity
        self.max_paths = self._calculate_dynamic_path_limit(operations, evmole_data)
        
        # Use our priority queue for path exploration
        self._execute_with_priorities(operations, evmole_data)
        
        # Post-process storage accesses
        self._post_process_storage_accesses()
        
        return self.storage_accesses
    
    def _calculate_dynamic_path_limit(self, operations: List, evmole_data: Dict) -> int:
        """Calculate a dynamic path limit based on contract complexity."""
        base_limit = DEFAULT_MAX_PATHS
        
        # Adjust based on code size
        code_size_factor = len(operations) / 1000  # Normalize by 1000 instructions
        
        # Adjust based on number of blocks
        num_blocks = len(evmole_data.get('blocks', {}))
        blocks_factor = num_blocks / 50  # Normalize by 50 blocks
        
        # Adjust based on number of storage-accessing blocks
        storage_factor = len(self.storage_accessing_blocks) / 10  # Normalize by 10 storage blocks
        
        # Combine factors with different weights
        adjustment = (code_size_factor * 0.3) + (blocks_factor * 0.5) + (storage_factor * 1.0)
        
        # Cap the adjustment to avoid excessive paths
        capped_adjustment = min(5.0, adjustment)  # Maximum 5x increase
        
        return int(base_limit * (1.0 + capped_adjustment))
    
    def _identify_storage_accessing_blocks(self, evmole_data: Dict, evmole_storage: List) -> None:
        """Identify which blocks are likely to access storage."""
        # Extract function selectors that access storage
        storage_functions = set()
        for record in evmole_storage:
            for selector in record.get('accessing_functions', {}).get('reads', []):
                storage_functions.add(selector)
            for selector in record.get('accessing_functions', {}).get('writes', []):
                storage_functions.add(selector)
        
        # Map functions to blocks
        function_blocks = evmole_data.get('function_blocks', {})
        for selector, blocks in function_blocks.items():
            if selector in storage_functions:
                self.storage_accessing_blocks.update(blocks)
    
    def _execute_with_priorities(self, operations: List, evmole_data: Dict) -> None:
        """Execute bytecode with prioritized path exploration."""
        from queue import PriorityQueue
        
        # Create priority queue for states
        priority_queue = PriorityQueue()
        
        # Start with initial state
        initial_state = ExecutionState()
        initial_priority = self._calculate_state_priority(initial_state, operations, evmole_data)
        
        # Priority queue uses negative priority for highest-first ordering
        priority_queue.put((-initial_priority, 0, initial_state))
        
        # Track a counter for tiebreaking same-priority states
        counter = 1
        
        while not priority_queue.empty() and self.execution_paths < self.max_paths:
            # Get highest priority state
            neg_priority, _, current_state = priority_queue.get()
            priority = -neg_priority  # Convert back to positive
            
            # Skip already explored states (path deduplication)
            state_hash = self._hash_state(current_state)
            if state_hash in self.explored_paths:
                continue
            
            self.explored_paths.add(state_hash)
            
            # Execute one step
            try:
                # Handle different categories of opcodes
                opcode_name, opcode_value, push_data, offset = operations[current_state.pc]
                
                # Process the opcode and generate new states
                new_states = self._execute_opcode(current_state, opcode_name, opcode_value, 
                                                 push_data, offset, operations)
                
                # Queue new states with priorities
                for new_state in new_states:
                    new_priority = self._calculate_state_priority(new_state, operations, evmole_data)
                    priority_queue.put((-new_priority, counter, new_state))
                    counter += 1
                
            except Exception as e:
                logger.error(f"Error executing at PC {current_state.pc}: {e}")
            
            self.execution_paths += 1
    
    def _calculate_state_priority(self, state: ExecutionState, operations: List, evmole_data: Dict) -> float:
        """Calculate a priority score for an execution state."""
        priority = 0.0
        
        # Base priority factors
        
        # 1. Is this state in a block known to access storage?
        current_block = self._find_containing_block(state.pc, evmole_data)
        if current_block in self.storage_accessing_blocks:
            priority += 100.0
        
        # 2. How close is this state to a storage operation?
        min_distance = self._calculate_distance_to_storage_op(state.pc, operations)
        if min_distance < float('inf'):
            priority += 50.0 / (1.0 + min_distance * 0.1)
        
        # 3. Has this state previously accessed storage?
        if hasattr(state, 'storage_access_count') and state.storage_access_count > 0:
            priority += 75.0 * state.storage_access_count
        
        # 4. Is this a new or recently discovered storage slot?
        if hasattr(state, 'last_storage_slot') and state.last_storage_slot is not None:
            if state.last_storage_slot not in self.storage_slots_accessed:
                priority += 200.0
        
        # 5. Penalty for states with many conditions (to favor simpler paths)
        condition_penalty = len(state.path_conditions) * 2.0
        priority -= condition_penalty
        
        return priority
    
    def _find_containing_block(self, pc: int, evmole_data: Dict) -> Optional[int]:
        """Find the block containing the given program counter."""
        for start, block_info in evmole_data.get('blocks', {}).items():
            if pc >= block_info['start'] and pc <= block_info['end']:
                return start
        return None
    
    def _calculate_distance_to_storage_op(self, pc: int, operations: List) -> float:
        """Calculate the minimum instruction distance to a storage operation."""
        min_distance = float('inf')
        
        # Look ahead in the code for storage operations
        for i, (opcode_name, _, _, offset) in enumerate(operations[pc:pc+50]):  # Limit lookahead
            if opcode_name in ('SLOAD', 'SSTORE'):
                min_distance = min(min_distance, i)
                
        return min_distance
    
    def _hash_state(self, state: ExecutionState) -> int:
        """Create a hash of the execution state for path deduplication."""
        # Simple implementation - a real one would need to consider more state aspects
        return hash((state.pc, tuple(c.value.get_id() if hasattr(c.value, 'get_id') 
                                    else str(c.value) for c in state.path_conditions)))
```

### 2.3 Improving Symbolic Execution Efficiency

To make symbolic execution more efficient, we'll leverage evmole's control flow graph and basic block information:

```python
# Additional methods for the EnhancedSymbolicExecutor class

def _execute_opcode(self, state: ExecutionState, opcode_name: str, opcode_value: int,
                   push_data: Optional[bytes], offset: int, operations: List) -> List[ExecutionState]:
    """Execute a single opcode and return resulting new states."""
    new_states = []
    
    # Track current state for storage access count
    if not hasattr(state, 'storage_access_count'):
        state.storage_access_count = 0
    
    if not hasattr(state, 'last_storage_slot'):
        state.last_storage_slot = None
    
    # Handle different categories of opcodes
    if opcode_name == 'SLOAD':
        # Process SLOAD - track storage access
        if len(state.stack) > 0:
            slot = state.pop()
            # Create storage access record
            access = StorageAccess('SLOAD', slot, pc=offset)
            self.storage_accesses.append(access)
            # Update state tracking
            state.storage_access_count += 1
            state.last_storage_slot = slot
            # Push symbolic result
            state.push(SymbolicValue())
        else:
            state.push(SymbolicValue())
        
        # Single result state with PC incremented
        state.pc += 1
        new_states.append(state)
        
    elif opcode_name == 'SSTORE':
        # Process SSTORE - track storage access
        if len(state.stack) >= 2:
            value, slot = state.pop(), state.pop()
            # Create storage access record
            access = StorageAccess('SSTORE', slot, value, pc=offset)
            self.storage_accesses.append(access)
            # Update state tracking
            state.storage_access_count += 1
            state.last_storage_slot = slot
        
        # Single result state with PC incremented
        state.pc += 1
        new_states.append(state)
    
    elif opcode_name == 'JUMPI':
        # Conditional jump - potentially create two paths
        if len(state.stack) >= 2:
            dest, cond = state.pop(), state.pop()
            
            # Check if we can determine the destination statically
            if dest.concrete:
                dest_val = dest.value
                
                # Create state for the true branch (taken jump)
                if not cond.concrete or cond.value != 0:
                    # Find JUMPDEST
                    jumpdest_found = False
                    for _, op_value, _, op_offset in operations:
                        if op_offset == dest_val and op_value == Opcode.JUMPDEST:
                            jumpdest_found = True
                            break
                    
                    if jumpdest_found:
                        true_state = state.clone()
                        true_state.pc = dest_val
                        # For symbolic conditions, add constraint
                        if not cond.concrete:
                            true_state.path_conditions.append(cond.value != 0)
                        new_states.append(true_state)
                
                # Always create state for the false branch (not taken)
                if not cond.concrete or cond.value == 0:
                    false_state = state.clone()
                    false_state.pc += 1
                    # For symbolic conditions, add constraint
                    if not cond.concrete:
                        false_state.path_conditions.append(cond.value == 0)
                    new_states.append(false_state)
            else:
                # Symbolic jump destination - conservatively just continue
                state.pc += 1
                new_states.append(state)
        else:
            # Stack underflow - just continue
            state.pc += 1
            new_states.append(state)
    
    # Handle other opcodes similarly...
    
    else:
        # Generic handling for other opcodes
        # (would need to implement all the other opcode handlers)
        # For now, just skip ahead
        state.pc += 1
        new_states.append(state)
    
    return new_states
```

### 2.4 Enhancing Type Inference

To improve type inference, we'll create a hybrid approach that combines evmole's static type analysis with our dynamic inference:

```python
# In src/tracer/storage_analyzer.py

class HybridTypeInference:
    """Type inference system that combines evmole static analysis with Z3-based dynamic inference."""
    
    def __init__(self, evmole_wrapper=None):
        """Initialize with an optional evmole wrapper instance."""
        self.evmole = evmole_wrapper or EvmoleWrapper()
        self.evmole_storage_info = {}
        self.type_confidence = {}
    
    def analyze_with_evmole(self, bytecode: str) -> None:
        """Analyze bytecode with evmole to extract storage types."""
        storage_layout = self.evmole.get_storage_layout(bytecode)
        
        # Convert to our internal format
        for record in storage_layout:
            slot = record['slot']
            self.evmole_storage_info[slot] = {
                'type': record['type'],
                'offset': record['offset'],
                'accessing_functions': record['accessing_functions']
            }
    
    def infer_variable_type(self, accesses: List[StorageAccess], original_inference: str) -> Tuple[str, float]:
        """
        Infer variable type using hybrid approach.
        
        Args:
            accesses: List of storage accesses
            original_inference: Type inferred by the original method
            
        Returns:
            Tuple of (inferred_type, confidence)
        """
        if not accesses:
            return "unknown", 0.0
        
        # Get the storage slot
        slot = accesses[0].slot
        slot_str = str(slot.value) if slot.concrete else str(slot)
        
        # Check if evmole has information for this slot
        evmole_type = None
        evmole_confidence = 0.0
        
        if slot_str in self.evmole_storage_info:
            evmole_type = self.evmole_storage_info[slot_str]['type']
            # Assign base confidence to evmole type
            evmole_confidence = 0.7  # Static analysis is good but not perfect
            
            # Adjust confidence based on whether functions access this storage
            accessing_functions = self.evmole_storage_info[slot_str]['accessing_functions']
            if accessing_functions['reads'] or accessing_functions['writes']:
                evmole_confidence += 0.1  # Boost confidence if we know which functions access it
        
        # Calculate confidence for original inference based on the evidence
        original_confidence = self._calculate_original_confidence(accesses, original_inference)
        
        # Decide which type to use
        if evmole_type and original_inference:
            if self._types_compatible(evmole_type, original_inference):
                # Types are compatible - use the more specific one with combined confidence
                specific_type = self._get_more_specific_type(evmole_type, original_inference)
                combined_confidence = min(1.0, evmole_confidence + original_confidence)
                return specific_type, combined_confidence
            else:
                # Types conflict - use the higher confidence one
                if evmole_confidence > original_confidence:
                    return evmole_type, evmole_confidence
                else:
                    return original_inference, original_confidence
        elif evmole_type:
            # Only have evmole type
            return evmole_type, evmole_confidence
        else:
            # Fall back to original inference
            return original_inference, original_confidence
    
    def _calculate_original_confidence(self, accesses: List[StorageAccess], inferred_type: str) -> float:
        """Calculate confidence score for the original type inference."""
        # Base confidence
        confidence = 0.5
        
        # Boost confidence based on number of accesses
        if len(accesses) > 5:
            confidence += 0.1
        elif len(accesses) > 10:
            confidence += 0.2
        
        # Boost confidence for concrete values that strongly indicate a type
        concrete_values = []
        for access in accesses:
            if access.op_type == 'SSTORE' and access.value and access.value.concrete:
                concrete_values.append(access.value.value)
        
        if concrete_values:
            # Check for boolean values
            if inferred_type == "bool" and all(v in (0, 1) for v in concrete_values):
                confidence += 0.3
            
            # Check for address values
            if inferred_type == "address" and all(v < (1 << 160) for v in concrete_values):
                confidence += 0.2
            
            # Check for small integers
            if inferred_type.startswith("uint") and len(set(concrete_values)) > 3:
                confidence += 0.1
        
        return min(1.0, confidence)
    
    def _types_compatible(self, type1: str, type2: str) -> bool:
        """Check if two types are compatible."""
        # Exact match
        if type1 == type2:
            return True
        
        # Check for uint compatibility
        if type1.startswith("uint") and type2.startswith("uint"):
            # Different bit sizes but same base type
            return True
        
        # Check for mapping compatibility
        if type1.startswith("mapping") and type2.startswith("mapping"):
            # Would need more sophisticated comparison for mappings
            return True
        
        # More compatibility checks would go here
        
        return False
    
    def _get_more_specific_type(self, type1: str, type2: str) -> str:
        """Get the more specific of two compatible types."""
        # For uint types, get the one with the more specific bit size
        if type1.startswith("uint") and type2.startswith("uint"):
            if type1 == "uint" or type1 == "uint256":
                return type2
            if type2 == "uint" or type2 == "uint256":
                return type1
            
            # Extract bit sizes and compare
            try:
                size1 = int(type1[4:])
                size2 = int(type2[4:])
                return type1 if size1 < size2 else type2  # Smaller is more specific
            except ValueError:
                pass
        
        # For now, prefer evmole type for other cases
        return type1
```

### 2.5 Integration into the Main Analysis Flow

Finally, we'll integrate these components into the main storage analyzer:

```python
# In src/tracer/storage_analyzer.py

class EnhancedStorageAnalyzer(StorageAnalyzer):
    """Enhanced storage analyzer that uses evmole integration."""
    
    def __init__(self, max_execution_paths: int = 100):
        """Initialize the enhanced storage analyzer."""
        super().__init__(max_execution_paths)
        # Replace standard executor with enhanced version
        self.executor = EnhancedSymbolicExecutor(max_paths=max_execution_paths)
        self.type_inference = HybridTypeInference()
    
    def analyze(self, bytecode: str) -> StorageLayout:
        """Analyze contract bytecode to determine storage layout."""
        # Validate bytecode
        if not bytecode or not isinstance(bytecode, str):
            raise ValueError("Bytecode must be a non-empty string")
        
        # Reset state
        self.layout = StorageLayout()
        
        # Perform evmole analysis first for type information
        self.type_inference.analyze_with_evmole(bytecode)
        
        logger.info("Running enhanced symbolic execution to collect storage accesses...")
        # Run symbolic execution to collect storage accesses
        storage_accesses = self.executor.analyze(bytecode)
        logger.info(f"Found {len(storage_accesses)} storage accesses")
        
        # Process storage accesses
        logger.info("Analyzing storage access patterns...")
        self._analyze_storage_accesses(storage_accesses)
        
        # Assign variable names based on patterns
        self._assign_variable_names()
        
        return self.layout
    
    def _infer_variable_type(self, accesses: List[StorageAccess]) -> str:
        """Enhanced variable type inference using hybrid approach."""
        # First use the original method to get a baseline
        original_type = super()._infer_variable_type(accesses)
        
        # Then apply hybrid inference
        enhanced_type, confidence = self.type_inference.infer_variable_type(accesses, original_type)
        
        logger.debug(f"Type inference: original={original_type}, enhanced={enhanced_type}, confidence={confidence:.2f}")
        
        return enhanced_type
```

## 3. Implementation Timeline

### Phase 1: Basic evmole Integration (2 weeks)
- Week 1: Add evmole dependency, create wrapper class
- Week 2: Implement basic storage layout extraction from evmole

### Phase 2: Enhanced Path Coverage (3 weeks)
- Week 3: Implement dynamic path limits and block identification
- Week 4: Develop priority-based execution engine
- Week 5: Add path deduplication and state merging

### Phase 3: Improved Type Inference (2 weeks)
- Week 6: Implement hybrid type inference system
- Week 7: Add compatibility rules and confidence scoring

### Phase 4: Testing and Optimization (2 weeks)
- Week 8: Comprehensive testing with varied contracts
- Week 9: Performance optimization and final integration

## 4. Metrics for Success

We will evaluate the success of this integration using the following metrics:

### 4.1 Path Coverage
- **Goal**: Increase coverage of unique storage slots by at least 30%
- **Measurement**: Compare number of discovered storage slots before and after integration

### 4.2 Execution Efficiency
- **Goal**: Reduce time to identify all storage slots by at least 50%
- **Measurement**: Compare execution time for benchmark contracts

### 4.3 Type Inference Accuracy
- **Goal**: Increase type identification accuracy to at least 90%
- **Measurement**: Validate against known contracts with verified source code

## 5. Assumptions and Limitations

1. **evmole Version Compatibility**: This integration assumes evmole supports the same EVM versions as our analyzer.

2. **Dependency Management**: The integration assumes evmole is properly installed and available.

3. **Type Resolution**: When evmole and Z3 inference conflict, we prioritize based on confidence scores, which may not always be correct.

4. **Control Flow Accuracy**: evmole's static analysis may not capture all dynamic behaviors, so we still need symbolic execution.

## 6. Future Enhancements

After this initial integration, several further enhancements could be considered:

1. **Machine Learning Integration**: Train a model on the combined features from both static and dynamic analysis.

2. **Interactive Feedback Loop**: Allow manual corrections to be fed back into the type inference system.

3. **Contract Similarity Analysis**: Use known contracts to improve analysis of similar unknown contracts.

4. **Decompiler Output Correlation**: Generate Solidity-like pseudocode for easier storage layout understanding.
