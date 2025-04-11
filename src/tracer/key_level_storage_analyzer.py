"""
Key-Level Storage Layout Analyzer for EVM contract bytecode.

This module extends the EnhancedStorageAnalyzer to provide analysis
at the storage key/index level for mappings and arrays.
"""

from typing import Dict, List, Optional, Set, Tuple, Union, Any, DefaultDict
import logging
from collections import defaultdict
import z3
from .enhanced_storage_analyzer import EnhancedStorageAnalyzer
from .storage_analyzer import (
    StorageLayout,
    StorageVariable,
    MappingVariable,
    ArrayVariable,
)
from .symbolic_tracer import StorageAccess, SymbolicValue

logger = logging.getLogger(__name__)


class KeyLevelMappingVariable(MappingVariable):
    """
    Represents a mapping variable with accesses grouped by key.
    """

    def __init__(
        self,
        slot: Union[int, str],
        key_type: Optional[str] = None,
        value_type: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        super().__init__(slot, key_type, value_type, name)
        # Store accesses grouped by the string representation of the symbolic key
        self.accesses_by_key: DefaultDict[str, List[StorageAccess]] = defaultdict(list)

    # Error: Method "add_access" overrides class "StorageVariable" in an incompatible manner
    # Rename to avoid signature conflict
    def add_key_access(self, access: StorageAccess, key_repr: str) -> None:
        """
        Add a storage access associated with a specific key.

        Args:
            access: The storage access to add.
            key_repr: The string representation of the symbolic key used in the access.
        """
        super().add_access(access)  # Keep track of all accesses in the parent class too
        self.accesses_by_key[key_repr].append(access)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the mapping to a dictionary, including key-level access info.
        """
        result = super().to_dict()
        # Optionally add key-level access details (might be too verbose)
        # result["accesses_by_key"] = {k: [str(a) for a in v] for k, v in self.accesses_by_key.items()}
        return result

    def __str__(self) -> str:
        """String representation including key access count."""
        base_str = super().__str__()
        key_count = len(self.accesses_by_key)
        return f"{base_str} (Accessed with {key_count} unique keys)"


class KeyLevelArrayVariable(ArrayVariable):
    """
    Represents an array variable with accesses grouped by index.
    """

    def __init__(
        self,
        slot: Union[int, str],
        element_type: Optional[str] = None,
        name: Optional[str] = None,
        length: Optional[int] = None,
    ) -> None:
        super().__init__(slot, element_type, name, length)
        # Store accesses grouped by the string representation of the symbolic index
        self.accesses_by_index: DefaultDict[str, List[StorageAccess]] = defaultdict(
            list
        )

    # Error: Method "add_access" overrides class "StorageVariable" in an incompatible manner
    # Rename to avoid signature conflict
    def add_index_access(self, access: StorageAccess, index_repr: str) -> None:
        """
        Add a storage access associated with a specific index.

        Args:
            access: The storage access to add.
            index_repr: The string representation of the symbolic index used in the access.
        """
        super().add_access(access)  # Keep track of all accesses in the parent class too
        self.accesses_by_index[index_repr].append(access)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the array to a dictionary, including index-level access info.
        """
        result = super().to_dict()
        # Optionally add index-level access details
        # result["accesses_by_index"] = {k: [str(a) for a in v] for k, v in self.accesses_by_index.items()}
        return result

    def __str__(self) -> str:
        """String representation including index access count."""
        base_str = super().__str__()
        index_count = len(self.accesses_by_index)
        return f"{base_str} (Accessed with {index_count} unique indices)"


class KeyLevelStorageAnalyzer(EnhancedStorageAnalyzer):
    """
    Analyzes contract storage layout, identifying accesses at the key/index level.
    """

    def __init__(self, max_execution_paths: int = 200, time_limit: int = 60):
        super().__init__(max_execution_paths, time_limit)
        # Override the layout object to ensure it can hold the new variable types
        self.layout = StorageLayout()  # Re-initialize layout

    def _extract_base_slot_and_key(
        self, slot_value: SymbolicValue
    ) -> Tuple[Union[int, str], Optional[str]]:
        """
        Attempts to extract the base slot and key/index from a symbolic slot value.

        Args:
            slot_value: The SymbolicValue representing the storage slot.

        Returns:
            A tuple containing:
            - The base slot (concrete int or string representation of base expression).
            - The key/index representation (string), or None if not applicable.
        """
        if slot_value.concrete:
            return slot_value.value, None  # Simple concrete slot

        # Check if it's a Z3 expression before accessing Z3 attributes
        if not isinstance(slot_value.value, z3.ExprRef):
            # Should not happen if not concrete, but handle defensively
            return str(slot_value.value), None

        # Now we know slot_value.value is a z3.ExprRef
        expr: z3.ExprRef = slot_value.value
        expr_str = str(z3.simplify(expr))  # Simplify for easier parsing

        # Pattern 1: Mapping (Keccak256)
        # Example: keccak256(key . base_slot)
        # We need to parse the Z3 expression tree. This is complex.
        # For now, let's use a simplified string parsing approach.
        # A more robust solution would involve traversing the Z3 AST.
        if z3.is_app_of(expr, z3.DeclareConst): # Check if it's a simple variable first
             pass # Handled by default case later
        elif z3.is_app_of(expr, z3.BitVecRef) and expr.decl().name() == "keccak256": # Check if it's keccak
             # TODO: Implement robust Z3 AST parsing for keccak arguments.
             # This requires traversing the expr tree to identify the base slot
             # and the key components based on their structure (e.g., concat).
             # For now, we call a placeholder and use a heuristic.
             base_slot_ast, key_repr_ast = self._parse_keccak_args_from_ast(expr)
             if base_slot_ast is not None:
                 # If AST parsing gives a base slot (even if symbolic), use it.
                 # key_repr_ast might be a simplified representation of the key part.
                 return base_slot_ast, key_repr_ast or expr_str # Fallback key_repr
             else:
                 # Fallback heuristic if AST parsing fails
                 logger.warning("Falling back to heuristic Keccak parsing.")
                 try:
                     # Look for concrete numbers inside the keccak expression string
                     import re
                     concrete_slots = [int(x) for x in re.findall(r"\b\d+\b", expr_str)]
                     if concrete_slots:
                         base_slot = min(concrete_slots) # Guess: smallest concrete is base
                         key_repr = expr_str # Use the whole expression as key for now
                         return base_slot, key_repr
                 except Exception:
                     pass # Fallback if heuristic fails
                 # Ultimate fallback: Use the whole expression as base, no specific key
                 return expr_str, None

        # Pattern 2: Array (Addition)
        # Example: base_slot + index
        # Error: Cannot access attribute "decl" for class "int" - Ensure expr is ExprRef
        if isinstance(expr, z3.BitVecRef) and expr.decl().name() == "+":
            num_args = expr.num_args()
            if num_args == 2:
                arg0, arg1 = expr.arg(0), expr.arg(1)
                # Assume one argument is the concrete base slot and the other is the index
                # Error: Cannot access attribute "arg" for class "int" - Already checked expr type
                if z3.is_int_value(arg0):
                    # Error: Cannot access attribute "as_long" for class "ExprRef" - Use as_long()
                    base_slot = arg0.as_long()
                    index_repr = str(z3.simplify(arg1))
                    return base_slot, index_repr
                elif z3.is_int_value(arg1):
                    # Error: Cannot access attribute "as_long" for class "ExprRef" - Use as_long()
                    base_slot = arg1.as_long()
                    index_repr = str(z3.simplify(arg0))
                    return base_slot, index_repr

        # Default: Treat the whole symbolic expression as the base slot
        return expr_str, None

    def _analyze_storage_accesses(self, accesses: List[StorageAccess]) -> None:
        """
        Analyze storage accesses to determine variable slots, types, and key/index usage.
        Overrides the base method to handle key-level grouping.
        """
        # Group accesses by BASE slot first
        base_slot_accesses: DefaultDict[Union[int, str], List[StorageAccess]] = (
            defaultdict(list)
        )
        access_details: Dict[
            int, Tuple[Union[int, str], Optional[str]]
        ] = {}  # Store details per access pc

        logger.info("Extracting base slots and keys/indices from accesses...")
        for access in accesses:
            base_slot, key_or_index_repr = self._extract_base_slot_and_key(access.slot)
            base_slot_accesses[base_slot].append(access)
            if access.pc is not None:
                access_details[access.pc] = (base_slot, key_or_index_repr)

        logger.info(f"Processing {len(base_slot_accesses)} unique base storage slots")

        # Process each base slot
        for base_slot, slot_accesses in base_slot_accesses.items():
            # Determine the type of variable (simple, mapping, array, packed, etc.)
            # This logic can reuse parts of the original _analyze_storage_accesses
            # but needs refinement based on the base_slot and the patterns in slot_accesses.

            is_mapping = any(a.is_mapping for a in slot_accesses)
            is_array = any(a.is_array for a in slot_accesses)
            is_packed = any(
                hasattr(a, "mask") and a.mask and a.mask != ((1 << 256) - 1)
                for a in slot_accesses
            )
            # TODO: Add struct detection if needed

            if is_mapping:
                self._analyze_key_level_mapping_slot(
                    base_slot, slot_accesses, access_details
                )
            elif is_array:
                self._analyze_key_level_array_slot(
                    base_slot, slot_accesses, access_details
                )
            # elif is_packed:
            #     # TODO: Adapt packed analysis if necessary
            #     self._analyze_packed_slot(base_slot, slot_accesses) # Use parent for now
            else:
                # Treat as simple slot for now, potentially refine later
                self._analyze_simple_slot(base_slot, slot_accesses)  # Use parent method

        # TODO: Re-integrate pattern detection (_detect_known_patterns, _detect_common_patterns)
        # Re-integrate pattern detection
        self._detect_known_patterns()
        self._detect_common_patterns()

    def _parse_keccak_args_from_ast(self, expr: z3.ExprRef) -> Tuple[Optional[Union[int, str]], Optional[str]]:
        """
        Placeholder for parsing Keccak256 arguments from Z3 AST.

        This should traverse the Z3 expression tree `expr` representing
        keccak256(concat(key_parts..., base_slot_bytes)) to extract the
        base slot (ideally concrete) and a representation of the key parts.

        Args:
            expr: The Z3 expression representing the keccak256 application.

        Returns:
            A tuple (base_slot, key_repr) where:
            - base_slot: Concrete int if found, or string representation of symbolic base.
            - key_repr: String representation of the key part(s).
            Returns (None, None) if parsing fails.
        """
        logger.warning(f"AST parsing for Keccak expression not fully implemented: {expr}")
        # Example of basic checks (needs actual traversal)
        # if expr.num_args() == 1 and expr.arg(0).decl().name() == 'concat':
        #     concat_args = expr.arg(0).children()
        #     # Try to find a concrete BitVecVal among the last args as base slot
        #     # Identify other args as key parts
        #     pass
        return None, None # Indicate parsing failure for now


    def _analyze_key_level_mapping_slot(
        self,
        base_slot: Union[int, str],
        accesses: List[StorageAccess],
        access_details: Dict[int, Tuple[Union[int, str], Optional[str]]],
    ) -> None:
        """
        Analyze accesses to a mapping slot at the key level.
        """
        logger.debug(
            f"Analyzing mapping base slot {base_slot} with {len(accesses)} accesses"
        )

        # Infer value type (can use parent method or enhanced one)
        value_type = self._infer_variable_type(accesses)
        key_type = "unknown"

        # Try to infer key type from accesses or key representation
        inferred_key_types: Set[str] = set()
        possible_keys: List[str] = []
        for access in accesses:
            if access.key_type:  # From symbolic tracer hints
                inferred_key_types.add(access.key_type)
            # Get key_repr for this access
            details = access_details.get(access.pc) if access.pc is not None else None
            key_repr = details[1] if details and details[1] is not None else None
            if key_repr:
                possible_keys.append(key_repr)
                # Basic inference based on key_repr format
                if key_repr.startswith("0x") and len(key_repr) == 42:
                    inferred_key_types.add("address")
                elif key_repr.isdigit() or (key_repr.startswith("bv") and key_repr[2:].isdigit()):
                     # Simple number or Z3 BitVecVal
                     inferred_key_types.add("uint256") # Default assumption
                # Add more patterns here (e.g., specific symbolic variable names)

        if len(inferred_key_types) == 1:
            key_type = inferred_key_types.pop()
        elif len(inferred_key_types) > 1:
            logger.warning(f"Conflicting inferred key types for slot {base_slot}: {inferred_key_types}")
            key_type = "mixed/unknown"
        else:
             # If no hints or patterns matched, keep as unknown
             key_type = "unknown"


        var = KeyLevelMappingVariable(base_slot, key_type, value_type)

        # Add accesses grouped by key
        keys_found = set()
        # Fix indentation error on the next line
        for access in accesses:
            details = access_details.get(access.pc) if access.pc is not None else None
            key_repr = (
                details[1] if details and details[1] is not None else "unknown_key"
            )
            # Update call to use renamed method
            var.add_key_access(access, key_repr)
            keys_found.add(key_repr)

        logger.debug(
            f"Mapping slot {base_slot} accessed with {len(keys_found)} unique keys."
        )
        self.layout.add_variable(var)

    def _analyze_key_level_array_slot(
        self,
        base_slot: Union[int, str],
        accesses: List[StorageAccess],
        access_details: Dict[int, Tuple[Union[int, str], Optional[str]]],
    ) -> None:
        """
        Analyze accesses to an array slot at the index level.
        """
        logger.debug(
            f"Analyzing array base slot {base_slot} with {len(accesses)} accesses"
        )

        # Infer element type
        element_type = self._infer_variable_type(accesses)

        var = KeyLevelArrayVariable(base_slot, element_type)

        # Add accesses grouped by index
        indices_found = set()
        # Fix indentation error on the next line
        for access in accesses:
            details = access_details.get(access.pc) if access.pc is not None else None
            index_repr = (
                details[1] if details and details[1] is not None else "unknown_index"
            )
            # Update call to use renamed method
            var.add_index_access(access, index_repr)
            indices_found.add(index_repr)

        logger.debug(
            f"Array slot {base_slot} accessed with {len(indices_found)} unique indices."
        )
        self.layout.add_variable(var)

    # We inherit analyze(), _assign_variable_names(), _infer_variable_type(),
    # _detect_known_patterns(), _detect_common_patterns(), etc. from EnhancedStorageAnalyzer
    # We override _analyze_storage_accesses and add specific key-level analysis methods.
    # We might need to override _analyze_simple_slot and _analyze_packed_slot if
    # the base slot extraction logic affects them significantly. For now, use parent's.


# Example usage (if run directly)
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # Example bytecode (replace with actual contract bytecode)
    # This is just a placeholder
    example_bytecode = "6080604052..."

    analyzer = KeyLevelStorageAnalyzer()

    try:
        layout = analyzer.analyze(example_bytecode)
        print("\n--- Key-Level Storage Layout ---")
        print(layout)

        print("\n--- Analysis Stats ---")
        stats = analyzer.get_analysis_stats()
        import json

        print(json.dumps(stats, indent=2))

    except ValueError as e:
        logger.error(f"Analysis failed: {e}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred during analysis: {e}")
