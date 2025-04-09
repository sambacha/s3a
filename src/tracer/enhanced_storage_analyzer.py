"""
Enhanced storage layout analyzer for EVM contract bytecode.

This module extends the base storage analyzer with improved path coverage,
execution efficiency, and type inference through evmole integration.
"""

from typing import Dict, List, Optional, Set, Tuple, Union, Any
import logging
import time

from .storage_analyzer import (
    StorageAnalyzer,
    StorageLayout,
    StorageVariable,
    MappingVariable,
    ArrayVariable,
)
from .enhanced_symbolic_tracer import EnhancedSymbolicExecutor
from .hybrid_type_inference import HybridTypeInference
from .symbolic_tracer import StorageAccess

logger = logging.getLogger(__name__)


class EnhancedStorageAnalyzer(StorageAnalyzer):
    """
    Enhanced storage analyzer that uses evmole integration for better accuracy and efficiency.

    This analyzer extends the base StorageAnalyzer with:
    - Guided path exploration through EnhancedSymbolicExecutor
    - Improved type inference through HybridTypeInference
    - Cross-validation of analysis results
    """

    def __init__(self, max_execution_paths: int = 200, time_limit: int = 60):
        """
        Initialize the enhanced storage analyzer.

        Args:
            max_execution_paths: Default maximum number of execution paths to explore
            time_limit: Time limit for analysis in seconds
        """
        # Initialize with parent class but replace the executor
        super().__init__(max_execution_paths)

        # Replace standard executor with enhanced version
        self.executor = EnhancedSymbolicExecutor(max_paths=max_execution_paths)
        self.executor.time_limit = time_limit

        # Add hybrid type inference
        self.type_inference = HybridTypeInference(evmole_wrapper=self.executor.evmole)

        # Add timing information
        self.start_time = None
        self.analysis_time = None

    def analyze(self, bytecode: str) -> StorageLayout:
        """
        Analyze contract bytecode to determine storage layout with enhanced accuracy.

        Args:
            bytecode: Hexadecimal string representing the bytecode

        Returns:
            StorageLayout object containing the detected layout

        Raises:
            ValueError: If the bytecode is invalid
        """
        # Start timer
        self.start_time = time.time()

        # Validate bytecode
        if not bytecode or not isinstance(bytecode, str):
            raise ValueError("Bytecode must be a non-empty string")

        # Reset state
        self.layout = StorageLayout()

        # Perform evmole analysis first for type information
        logger.info("Running evmole analysis for type information...")
        self.type_inference.analyze_with_evmole(bytecode)

        logger.info(
            "Running enhanced symbolic execution to collect storage accesses..."
        )
        # Run symbolic execution to collect storage accesses
        storage_accesses = self.executor.analyze(bytecode)
        logger.info(f"Found {len(storage_accesses)} storage accesses")

        # Process storage accesses
        logger.info("Analyzing storage access patterns...")
        self._analyze_storage_accesses(storage_accesses)

        # Assign variable names based on patterns
        self._assign_variable_names()

        # Record analysis time
        self.analysis_time = time.time() - self.start_time
        logger.info(
            f"Storage layout analysis completed in {self.analysis_time:.2f} seconds"
        )

        # Log type inference statistics
        stats = self.type_inference.get_inference_stats()
        logger.info(
            f"Type inference enhanced {stats['enhancements']} variables and resolved {stats['conflicts']} conflicts"
        )

        return self.layout

    def _infer_variable_type(self, accesses: List[StorageAccess]) -> str:
        """
        Enhanced variable type inference using hybrid approach.

        Args:
            accesses: List of storage accesses

        Returns:
            Inferred type as string
        """
        # First use the original method to get a baseline
        original_type = super()._infer_variable_type(accesses)

        # Then apply hybrid inference
        enhanced_type, confidence = self.type_inference.infer_variable_type(
            accesses, original_type
        )

        logger.debug(
            f"Type inference: original={original_type}, enhanced={enhanced_type}, confidence={confidence:.2f}"
        )

        return enhanced_type

    def get_analysis_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the analysis process.

        Returns:
            Dictionary with analysis statistics
        """
        stats = {
            "analysis_time": self.analysis_time,
            "execution_paths": self.executor.execution_paths,
            "storage_variables": len(self.layout.variables),
            "storage_accesses": len(self.executor.storage_accesses),
        }

        # Add type inference stats
        type_stats = self.type_inference.get_inference_stats()
        stats.update(type_stats)

        # Count variable types
        var_types = {}
        for var in self.layout.variables:
            var_type = var.var_type
            if isinstance(var, MappingVariable):
                var_type = "mapping"
            elif isinstance(var, ArrayVariable):
                var_type = "array"

            if var_type not in var_types:
                var_types[var_type] = 0
            var_types[var_type] += 1

        stats["variable_types"] = var_types

        return stats
