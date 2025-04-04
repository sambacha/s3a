# core/concrete.py
from typing import Dict, List, Optional, Any, Union
from web3 import Web3
import json
import structlog

logger = structlog.get_logger()

# Known DEX addresses and method IDs (move to patterns.py later)
# TODO: Move these definitions to swap_detection/patterns.py
DEX_ADDRESSES = {
    "mainnet": [
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
        "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f",  # SushiSwap Router
        # Add other known DEX router addresses
    ],
    "goerli": [
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", # Uniswap V2 Router (same on Goerli)
        "0xe592427a0aece92de3edee1f18e0157c05861564", # Uniswap V3 Router (same on Goerli)
        # Add other testnet DEX routers
    ]
}

SWAP_METHOD_IDS = [
    "0x38ed1739",  # swapExactTokensForTokens
    "0x7ff36ab5",  # swapExactETHForTokens
    "0x18cbafe5",  # swapExactTokensForETH
    "0x414bf389",  # exactInputSingle (V3)
    "0xc04b8d59",  # exactInput (V3)
    "0x5f575529",  # swapExactTokensForTokensSupportingFeeOnTransferTokens (V2)
    "0xfb3bdb41",  # swapETHForExactTokens (V2)
    "0xb6f9de95",  # swapExactTokensForETHSupportingFeeOnTransferTokens (V2)
    # Add other known swap method IDs
]

TOKEN_TRANSFER_METHOD_IDS = ["0xa9059cbb", "0x23b872dd"]  # transfer, transferFrom

class ConcreteExecutor:
    def __init__(self, web3_provider_url: str, network: str = "mainnet"):
        self.web3 = Web3(Web3.HTTPProvider(web3_provider_url))
        self.network = network
        if not self.web3.is_connected():
             logger.error("Failed to connect to Web3 provider", url=web3_provider_url)
             raise ConnectionError(f"Could not connect to Web3 provider at {web3_provider_url}")
        logger.info("Connected to Web3 provider", url=web3_provider_url, network=network)

    def trace_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """Execute a transaction concretely and get detailed execution trace using debug_traceTransaction"""
        logger.debug("Tracing transaction concretely", tx_hash=tx_hash)
        try:
            # Using callTracer with logs enabled to capture events within the trace
            trace = self.web3.provider.make_request(
                "debug_traceTransaction",
                [tx_hash, {
                    "tracer": "callTracer",
                    "tracerConfig": {
                        "withLog": True # Include logs in the trace output
                    }
                }]
            )
        except Exception as e:
            logger.exception("Error calling debug_traceTransaction", tx_hash=tx_hash, error=str(e))
            raise

        if "error" in trace:
            logger.error("Error received from debug_traceTransaction", tx_hash=tx_hash, error=trace["error"])
            raise Exception(f"Trace error for {tx_hash}: {trace['error']}")

        if "result" not in trace:
             logger.error("Unexpected trace format: 'result' key missing", tx_hash=tx_hash, trace_response=trace)
             raise ValueError(f"Unexpected trace format received for {tx_hash}")

        logger.debug("Successfully traced transaction", tx_hash=tx_hash)
        return trace["result"] # The result field contains the call trace structure

    def extract_points_of_interest(self, trace: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract points of interest (potential swap-related calls) from a concrete trace"""
        points = []
        logger.debug("Extracting points of interest from trace")

        def process_call(call_frame: Dict[str, Any], depth: int = 0):
            # Check if this call frame itself is interesting
            if self._is_potential_swap_call(call_frame):
                # Extract relevant info from the frame
                poi = {
                    # PC is often not available in callTracer, use other info
                    "type": call_frame.get("type", "CALL"), # CALL, DELEGATECALL, etc.
                    "from": call_frame.get("from", "").lower(),
                    "to": call_frame.get("to", "").lower(),
                    "input": call_frame.get("input", "0x"),
                    "output": call_frame.get("output", "0x"),
                    "value": call_frame.get("value", "0x0"), # Hex string value
                    "gas": call_frame.get("gas", "0x0"), # Hex string gas provided
                    "gasUsed": call_frame.get("gasUsed", "0x0"), # Hex string gas used
                    "call_depth": depth,
                    "logs": call_frame.get("logs", []), # Logs emitted by this call frame
                    "error": call_frame.get("error") # Potential error message
                }
                points.append(poi)
                logger.debug("Found potential point of interest", poi_details=poi)

            # Recursively process nested calls
            for sub_call in call_frame.get("calls", []):
                process_call(sub_call, depth + 1)

        # Start processing from the top-level call frame
        process_call(trace)
        logger.info(f"Extracted {len(points)} potential points of interest from trace.")
        return points

    def _is_potential_swap_call(self, call: Dict[str, Any]) -> bool:
        """Determine if a call frame potentially relates to token swapping"""
        to_address = call.get("to", "").lower()
        input_data = call.get("input", "0x")

        # 1. Check destination address against known DEX routers for the network
        network_dex_addresses = DEX_ADDRESSES.get(self.network, [])
        if to_address in network_dex_addresses:
            logger.debug("POI check: Matched known DEX address", address=to_address)
            return True

        # 2. Check method signature for common swap methods
        if input_data and len(input_data) >= 10:  # "0x" + 8 chars for method ID
            method_id = input_data[0:10].lower()
            if method_id in SWAP_METHOD_IDS:
                logger.debug("POI check: Matched known swap method ID", method_id=method_id, address=to_address)
                return True

        # 3. Check for token transfer calls (transfer/transferFrom) which are part of swaps
        if input_data and len(input_data) >= 10:
            method_id = input_data[0:10].lower()
            if method_id in TOKEN_TRANSFER_METHOD_IDS:
                 # Could refine this: check if 'from' or 'to' in transferFrom is a DEX?
                 logger.debug("POI check: Matched token transfer method ID", method_id=method_id, address=to_address)
                 return True # Consider transfers as potentially relevant

        # 4. Check logs within the call frame for Swap events (less common for callTracer, but possible)
        # This might be redundant if logs are checked separately, but adds robustness.
        for log in call.get("logs", []):
            topics = log.get("topics", [])
            if topics:
                event_sig_hash = topics[0].hex() if isinstance(topics[0], bytes) else topics[0]
                # TODO: Use event signatures from patterns.py
                uniswap_v2_swap_event = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
                uniswap_v3_swap_event = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
                if event_sig_hash in [uniswap_v2_swap_event, uniswap_v3_swap_event]:
                    logger.debug("POI check: Found Swap event log within call frame", event_hash=event_sig_hash, address=to_address)
                    return True

        return False

    def get_transaction_details(self, tx_hash: str) -> Dict[str, Any]:
        """Fetch transaction details"""
        logger.debug("Fetching transaction details", tx_hash=tx_hash)
        try:
            tx = self.web3.eth.get_transaction(tx_hash)
            if tx is None:
                raise ValueError(f"Transaction not found: {tx_hash}")
            # Convert AttributeDict to standard dict for easier processing/serialization
            return dict(tx)
        except Exception as e:
            logger.exception("Error fetching transaction details", tx_hash=tx_hash, error=str(e))
            raise

    def get_transaction_receipt(self, tx_hash: str) -> Dict[str, Any]:
        """Fetch transaction receipt"""
        logger.debug("Fetching transaction receipt", tx_hash=tx_hash)
        try:
            receipt = self.web3.eth.get_transaction_receipt(tx_hash)
            if receipt is None:
                raise ValueError(f"Transaction receipt not found: {tx_hash}")
            # Convert AttributeDict to standard dict
            return dict(receipt)
        except Exception as e:
            logger.exception("Error fetching transaction receipt", tx_hash=tx_hash, error=str(e))
            raise

    def get_contract_code(self, contract_address: str) -> bytes:
        """Fetch contract bytecode"""
        logger.debug("Fetching contract code", address=contract_address)
        try:
            code = self.web3.eth.get_code(contract_address)
            return code
        except Exception as e:
            logger.exception("Error fetching contract code", address=contract_address, error=str(e))
            raise

    def get_block_context(self, block_identifier: Union[str, int] = 'latest') -> Dict[str, Any]:
        """Fetch block details for context"""
        logger.debug("Fetching block context", block=block_identifier)
        try:
            block = self.web3.eth.get_block(block_identifier)
            if block is None:
                raise ValueError(f"Block not found: {block_identifier}")
            # Convert AttributeDict to standard dict
            return dict(block)
        except Exception as e:
            logger.exception("Error fetching block context", block=block_identifier, error=str(e))
            raise

    # Add methods for getting balances if needed for concrete initialization
    def get_eth_balance(self, address: str, block_identifier: Union[str, int] = 'latest') -> int:
        logger.debug("Fetching ETH balance", address=address, block=block_identifier)
        try:
            balance = self.web3.eth.get_balance(address, block_identifier=block_identifier)
            return balance
        except Exception as e:
            logger.exception("Error fetching ETH balance", address=address, block=block_identifier, error=str(e))
            raise

    # Getting token balances requires contract interaction (ABI)
    # This might be better placed in a dedicated token utility class
    # def get_token_balance(self, token_address: str, user_address: str, block_identifier: Union[str, int] = 'latest') -> int:
    #     # Requires ERC20 ABI
    #     erc20_abi = [...] # Standard ERC20 ABI
    #     token_contract = self.web3.eth.contract(address=token_address, abi=erc20_abi)
    #     try:
    #         balance = token_contract.functions.balanceOf(user_address).call(block_identifier=block_identifier)
    #         return balance
    #     except Exception as e:
    #         logger.exception("Error fetching token balance", token=token_address, user=user_address, block=block_identifier, error=str(e))
    #         raise
