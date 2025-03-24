"""
Hybrid type inference system combining static and dynamic analysis.

This module provides enhanced type inference for storage variables by
combining evmole's static analysis with Z3-based dynamic inference.
"""

from typing import Dict, List, Optional, Set, Tuple, Union, Any
import logging
import re

from .evmole_integration import EvmoleWrapper
from .symbolic_tracer import StorageAccess, SymbolicValue

logger = logging.getLogger(__name__)

class HybridTypeInference:
    """
    Type inference system that combines evmole static analysis with Z3-based dynamic inference.
    
    This hybrid approach provides more accurate type information by cross-validating
    static and dynamic analysis results, and using confidence scoring to resolve conflicts.
    """
    
    def __init__(self, evmole_wrapper=None):
        """
        Initialize with an optional evmole wrapper instance.
        
        Args:
            evmole_wrapper: Optional EvmoleWrapper instance to use for static analysis
        """
        self.evmole = evmole_wrapper or EvmoleWrapper()
        self.evmole_storage_info = {}
        self.type_confidence = {}
        self.original_inference_results = {}
    
    def analyze_with_evmole(self, bytecode: str) -> None:
        """
        Analyze bytecode with evmole to extract storage types.
        
        Args:
            bytecode: Contract bytecode as hex string
        """
        storage_layout = self.evmole.get_storage_layout(bytecode)
        logger.info(f"Evmole provided type information for {len(storage_layout)} storage slots")
        
        # Convert to our internal format
        for record in storage_layout:
            slot = record['slot']
            self.evmole_storage_info[slot] = {
                'type': record['type'],
                'offset': record['offset'],
                'accessing_functions': record['accessing_functions']
            }
            logger.debug(f"Evmole identified slot {slot} as type {record['type']}")
    
    def infer_variable_type(self, accesses: List[StorageAccess], original_inference: str) -> Tuple[str, float]:
        """
        Infer variable type using hybrid approach.
        
        Args:
            accesses: List of storage accesses to analyze
            original_inference: Type inferred by the original method
            
        Returns:
            Tuple of (inferred_type, confidence)
        """
        if not accesses:
            return "unknown", 0.0
        
        # Get the storage slot
        slot = accesses[0].slot
        slot_str = str(slot.value) if slot.concrete else str(slot)
        
        # Store original inference for future reference
        self.original_inference_results[slot_str] = original_inference
        
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
            
            logger.debug(f"Evmole suggests type {evmole_type} for slot {slot_str} with confidence {evmole_confidence:.2f}")
        
        # Calculate confidence for original inference based on the evidence
        original_confidence = self._calculate_original_confidence(accesses, original_inference)
        logger.debug(f"Original inference suggests type {original_inference} for slot {slot_str} with confidence {original_confidence:.2f}")
        
        # Decide which type to use
        if evmole_type and original_inference:
            if self._types_compatible(evmole_type, original_inference):
                # Types are compatible - use the more specific one with combined confidence
                specific_type = self._get_more_specific_type(evmole_type, original_inference)
                combined_confidence = min(1.0, evmole_confidence + original_confidence)
                logger.info(f"Combining compatible types {evmole_type} and {original_inference} -> {specific_type} with confidence {combined_confidence:.2f}")
                return specific_type, combined_confidence
            else:
                # Types conflict - use the higher confidence one
                if evmole_confidence > original_confidence:
                    logger.info(f"Type conflict resolved in favor of evmole: {evmole_type} (confidence: {evmole_confidence:.2f}) vs {original_inference} (confidence: {original_confidence:.2f})")
                    return evmole_type, evmole_confidence
                else:
                    logger.info(f"Type conflict resolved in favor of original inference: {original_inference} (confidence: {original_confidence:.2f}) vs {evmole_type} (confidence: {evmole_confidence:.2f})")
                    return original_inference, original_confidence
        elif evmole_type:
            # Only have evmole type
            logger.info(f"Using evmole type only: {evmole_type} (confidence: {evmole_confidence:.2f})")
            return evmole_type, evmole_confidence
        else:
            # Fall back to original inference
            logger.info(f"No evmole data, using original inference: {original_inference} (confidence: {original_confidence:.2f})")
            return original_inference, original_confidence
    
    def _calculate_original_confidence(self, accesses: List[StorageAccess], inferred_type: str) -> float:
        """
        Calculate confidence score for the original type inference.
        
        Args:
            accesses: List of storage accesses
            inferred_type: Type inferred by original method
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
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
            
            # Check for consistent values (suggests an enum)
            if len(set(concrete_values)) < len(concrete_values) / 2 and len(concrete_values) > 4:
                confidence += 0.1
        
        return min(1.0, confidence)
    
    def _types_compatible(self, type1: str, type2: str) -> bool:
        """
        Check if two types are compatible.
        
        Args:
            type1: First type
            type2: Second type
            
        Returns:
            True if types are compatible, False otherwise
        """
        # Exact match
        if type1 == type2:
            return True
        
        # Check for uint compatibility
        if type1.startswith("uint") and type2.startswith("uint"):
            # Different bit sizes but same base type
            return True
        
        # Check for int compatibility
        if type1.startswith("int") and type2.startswith("int"):
            # Different bit sizes but same base type
            return True
        
        # Check for mapping compatibility
        if type1.startswith("mapping") and type2.startswith("mapping"):
            # Simple check for mapping compatibility
            return True
        
        # Check for array compatibility
        if "[]" in type1 and "[]" in type2:
            # Simple check for array compatibility
            return True
        
        # Special case: address and uint160 are compatible
        if (type1 == "address" and type2 == "uint160") or (type1 == "uint160" and type2 == "address"):
            return True
        
        # Special case: bytes and string are compatible (both dynamic)
        if (type1 == "bytes" and type2 == "string") or (type1 == "string" and type2 == "bytes"):
            return True
        
        return False
    
    def _get_more_specific_type(self, type1: str, type2: str) -> str:
        """
        Get the more specific of two compatible types.
        
        Args:
            type1: First type
            type2: Second type
            
        Returns:
            The more specific type
        """
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
        
        # For int types, similar logic
        if type1.startswith("int") and type2.startswith("int"):
            if type1 == "int" or type1 == "int256":
                return type2
            if type2 == "int" or type2 == "int256":
                return type1
            
            # Extract bit sizes and compare
            try:
                size1 = int(type1[3:])
                size2 = int(type2[3:])
                return type1 if size1 < size2 else type2  # Smaller is more specific
            except ValueError:
                pass
        
        # For mapping types, evmole might have more detailed key/value types
        if type1.startswith("mapping") and type2.startswith("mapping"):
            # Check which has more detailed key/value types (more characters)
            return type1 if len(type1) > len(type2) else type2
        
        # For arrays, prefer ones with element type specified
        if "[]" in type1 and "[]" in type2:
            # Check which has more detailed element type
            return type1 if len(type1) > len(type2) else type2
        
        # Special cases
        if (type1 == "address" and type2 == "uint160"):
            return "address"  # address is more specific than uint160
        if (type1 == "uint160" and type2 == "address"):
            return "address"  # address is more specific than uint160
        
        # For bytes vs string, prefer the more specific one
        if (type1 == "bytes" and type2 == "string"):
            return type2  # string is more specific
        if (type1 == "string" and type2 == "bytes"):
            return type1  # string is more specific
        
        # Prefer evmole type by default (first parameter)
        return type1
    
    def get_inference_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the type inference results.
        
        Returns:
            Dictionary with inference statistics
        """
        stats = {
            'total_slots': len(self.original_inference_results),
            'evmole_slots': len(self.evmole_storage_info),
            'conflicts': 0,
            'enhancements': 0,
        }
        
        # Count conflicts and enhancements
        for slot, original_type in self.original_inference_results.items():
            if slot in self.evmole_storage_info:
                evmole_type = self.evmole_storage_info[slot]['type']
                if not self._types_compatible(original_type, evmole_type):
                    stats['conflicts'] += 1
                elif self._get_more_specific_type(evmole_type, original_type) != original_type:
                    stats['enhancements'] += 1
        
        return stats
