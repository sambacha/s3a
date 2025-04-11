#!/usr/bin/env python3
"""
Access List Generator for Ethereum Transactions.

This module provides functionality to generate EIP-2930 access lists
from transaction traces, which can be used to optimize gas usage
for transactions that access the same storage slots repeatedly.
"""

import logging
import json
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from web3 import Web3

# Make sure we can be imported from anywhere
if __name__ == "__main__":
    import sys
    import os
    # Add the parent directory to sys.path
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

logger = logging.getLogger(__name__)

def generate_access_list(web3: Web3, tx_hash: str) -> List[Dict[str, Any]]:
    """
    Generates an EIP-2930 access list for a given transaction hash.

    Args:
        web3: Connected Web3 instance.
        tx_hash: The transaction hash as a hex string.

    Returns:
        A list formatted according to EIP-2930.

    Raises:
        ValueError: If the trace cannot be retrieved or parsed.
        Exception: For other web3 or processing errors.
    """
    logger.info(f"Fetching trace for transaction {tx_hash}...")
    try:
        # Use default tracer which includes structLogs with storage
        trace = web3.provider.make_request("debug_traceTransaction", [tx_hash])
        if "result" not in trace:
             raise ValueError(f"Failed to get trace for {tx_hash}. Response: {trace.get('error', 'Unknown error')}")
        struct_logs = trace["result"].get("structLogs")
        if not struct_logs:
            raise ValueError(f"No structLogs found in trace for {tx_hash}")

    except Exception as e:
        logger.error(f"Error fetching or parsing trace: {e}")
        return [] # Return empty list on error

    logger.info(f"Processing {len(struct_logs)} trace steps...")
    access_list_data: Dict[str, Set[str]] = defaultdict(set) # address -> set(keys)

    # Pre-populate with sender and receiver
    sender: Optional[str] = None # Initialize to None
    receiver: Optional[str] = None # Initialize to None
    try:
        tx_data = web3.eth.get_transaction(tx_hash)
        sender = tx_data.get('from')
        receiver = tx_data.get('to')
        if sender:
            access_list_data[web3.to_checksum_address(sender)] # Ensure sender is present
        if receiver:
            access_list_data[web3.to_checksum_address(receiver)] # Ensure receiver is present
    except Exception as e:
        logger.warning(f"Could not get transaction details to pre-populate sender/receiver: {e}")

    # Process trace logs to extract storage accesses
    call_stack = [] # To keep track of current contract context
    storage_accesses = {} # Map of addresses to their accessed storage slots

    for i, log in enumerate(struct_logs):
        # Track call stack depth to determine current address context
        depth = log.get("depth")
        op = log.get("op")

        # Update call stack (simplified)
        # A more robust method would parse CALL/CREATE inputs fully
        if len(call_stack) < depth:
             # Inferring called address is complex from default trace, might need callTracer
             # For now, we rely on SLOAD/SSTORE context if available
             pass # Placeholder for now
        elif len(call_stack) > depth:
             call_stack = call_stack[:depth] # Returned from call

        # Process storage operations
        if op in ("SLOAD", "SSTORE"):
            stack = log.get("stack", [])
            if stack:
                # Get storage slot from stack
                try:
                    # For SLOAD: key is at stack[-1]
                    # For SSTORE: key is at stack[-1] for new EVM versions, stack[-2] for older ones
                    slot_index = -1 if op == "SLOAD" else -2
                    slot = stack[slot_index]
                    
                    # If we have a current address context, record the storage access
                    if receiver:  # Fallback to using the receiver as context
                        address = web3.to_checksum_address(receiver)
                        # Convert slot to 0x-prefixed hex string with leading zeros
                        hex_slot = "0x" + hex(int(slot, 16) if isinstance(slot, str) else int(slot))[2:].zfill(64)
                        access_list_data[address].add(hex_slot)
                except (IndexError, ValueError) as e:
                    logger.debug(f"Error processing {op} at step {i}: {e}")
                    continue

    # Convert the collected data to EIP-2930 access list format
    # Format: [{"address": "0x...", "storageKeys": ["0x...", "0x..."]}, ...]
    access_list = []
    for address, slots in access_list_data.items():
        if slots:  # Only include addresses with storage accesses
            access_list.append({
                "address": address,
                "storageKeys": list(slots)
            })
        else:
            # Include address-only entries for those without storage accesses
            access_list.append({
                "address": address,
                "storageKeys": []
            })

    logger.info(f"Generated access list with {len(access_list)} addresses")
    return access_list

def format_access_list(access_list: List[Dict[str, Any]], pretty: bool = True) -> str:
    """
    Formats an access list as a JSON string.
    
    Args:
        access_list: The access list to format
        pretty: Whether to prettify the output
        
    Returns:
        A JSON string representation of the access list
    """
    import json
    indent = 2 if pretty else None
    return json.dumps(access_list, indent=indent)
