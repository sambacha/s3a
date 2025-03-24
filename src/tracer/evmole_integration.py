"""
Integration module for evmole decompiler with Z3 SMT storage analyzer.

This module provides a wrapper for evmole functionality to enhance
the symbolic execution and storage layout analysis capabilities.
"""

from typing import Dict, List, Optional, Any, Union, Tuple
import logging

# Try to import evmole, but handle the case when it's not installed
try:
    import evmole
    EVMOLE_AVAILABLE = True
except ImportError:
    EVMOLE_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("evmole package not installed. Enhanced analysis features will be limited.")

logger = logging.getLogger(__name__)

class EvmoleWrapper:
    """Wrapper for evmole functionality to integrate with our analyzer."""
    
    def __init__(self):
        """Initialize the evmole wrapper."""
        self.last_analysis = None
    
    def analyze_bytecode(self, bytecode: Union[bytes, str]) -> Any:
        """
        Run a complete evmole analysis on the provided bytecode.
        
        Args:
            bytecode: Contract bytecode as hex string or bytes
            
        Returns:
            Analysis result from evmole or None if evmole is not available
        """
        if not EVMOLE_AVAILABLE:
            logger.warning("evmole not available for analyzing bytecode")
            return None
            
        try:
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
        except Exception as e:
            logger.error(f"Error during evmole analysis: {e}")
            # Return an empty analysis result
            return None
    
    def get_storage_layout(self, bytecode: Union[bytes, str]) -> List[Dict[str, Any]]:
        """
        Extract storage layout information from bytecode.
        
        Args:
            bytecode: Contract bytecode as hex string or bytes
            
        Returns:
            List of storage records with slot, offset, type, and accessing functions
        """
        if not EVMOLE_AVAILABLE:
            logger.warning("evmole not available for extracting storage layout")
            return []
            
        analysis = self.analyze_bytecode(bytecode)
        if not analysis or not analysis.storage:
            logger.warning("No storage layout information found in evmole analysis")
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
            
        logger.info(f"Extracted {len(result)} storage records from evmole analysis")
        return result
    
    def get_control_flow_data(self, bytecode: Union[bytes, str]) -> Dict[str, Any]:
        """
        Extract control flow information to guide path exploration.
        
        Args:
            bytecode: Contract bytecode as hex string or bytes
            
        Returns:
            Dictionary with blocks and function mapping information
        """
        if not EVMOLE_AVAILABLE:
            logger.warning("evmole not available for extracting control flow data")
            return {}
            
        analysis = self.analyze_bytecode(bytecode)
        if not analysis or not analysis.control_flow_graph:
            logger.warning("No control flow graph found in evmole analysis")
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
        
        logger.info(f"Extracted {len(blocks_by_start)} blocks and {len(function_blocks)} functions from control flow graph")
        return {
            'blocks': blocks_by_start,
            'function_blocks': function_blocks
        }
    
    def _get_block_type_info(self, btype) -> Dict[str, Any]:
        """
        Convert block type to dictionary representation.
        
        Args:
            btype: Block type from evmole analysis
            
        Returns:
            Dictionary representation of the block type
        """
        if not EVMOLE_AVAILABLE:
            return {'type': 'unknown'}
            
        try:
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
        except Exception as e:
            logger.error(f"Error processing block type: {e}")
            return {'type': 'error', 'message': str(e)}
    
    def _format_dynamic_jump(self, jump) -> Dict[str, Any]:
        """
        Format dynamic jump information.
        
        Args:
            jump: Dynamic jump from evmole analysis
            
        Returns:
            Dictionary representation of the dynamic jump
        """
        return {'path': jump.path, 'to': jump.to}
    
    def _find_blocks_for_function(self, offset: int, blocks_by_start: Dict[int, Dict]) -> List[int]:
        """
        Find blocks that belong to a function starting at the given offset.
        
        This is a simplified implementation - a more sophisticated version would
        trace through the control flow graph to find all blocks reachable from
        the function entry point.
        
        Args:
            offset: Function bytecode offset
            blocks_by_start: Dictionary of blocks by start offset
            
        Returns:
            List of block offsets that belong to the function
        """
        result = []
        
        # First, find the entry block
        entry_block = None
        for start, block in blocks_by_start.items():
            if start == offset:
                entry_block = block
                result.append(start)
                break
        
        # If we didn't find an exact match, find the closest preceding block
        if not entry_block:
            preceding_offsets = [s for s in blocks_by_start.keys() if s <= offset]
            if preceding_offsets:
                closest_offset = max(preceding_offsets)
                entry_block = blocks_by_start[closest_offset]
                result.append(closest_offset)
        
        # Without full CFG traversal, we'll use a simple heuristic:
        # Include blocks that are likely part of the same function based on proximity
        if entry_block:
            # Get potential function end
            potential_end = entry_block['end'] + 500  # Arbitrarily assume function size < 500 bytes
            
            # Add blocks that fall within the potential function range
            for start, block in blocks_by_start.items():
                if start > offset and start < potential_end and start not in result:
                    result.append(start)
        
        return sorted(result)
