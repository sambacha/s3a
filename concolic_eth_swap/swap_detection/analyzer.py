# swap_detection/analyzer.py
import time # Import time module
# swap_detection/analyzer.py
import time # Import time module
from typing import Dict, List, Any, Tuple, Optional
import structlog
from web3 import Web3
from web3.exceptions import TransactionNotFound
# Import evmole's decoder
from evmole import decode_function_input
from eth_utils import function_signature_to_4byte_selector, is_hex, to_checksum_address, to_bytes

# Use relative imports within the package
from ..core.concolic import ConcolicExecutor
from .patterns import (
    is_eth_usdc_path,
    get_method_info,
    get_event_info,
    is_known_eth_usdc_pool,
    get_token_address,
    SwapMethodSignature,
    SwapEventSignature,
    DEX_ROUTER_ADDRESSES # Import DEX_ROUTER_ADDRESSES
)
# Assuming ContractDB might be useful here, though not explicitly used yet
from ..ethereum.contract_db import ContractDB
# Assuming TokenUtils might be useful
from ..ethereum.token_utils import TokenUtils


logger = structlog.get_logger()

class SwapAnalyzer:
    def __init__(self, web3_provider_url: str, network: str = "mainnet", contract_db_path: Optional[str] = None):
        self.concolic_executor = ConcolicExecutor(web3_provider_url, network)
        # Keep a direct web3 instance for quick checks (receipts, basic tx info)
        self.web3 = Web3(Web3.HTTPProvider(web3_provider_url))
        if not self.web3.is_connected():
             raise ConnectionError(f"Failed to connect to Web3 provider at {web3_provider_url}")
        self.network = network
        self.contract_db = ContractDB(db_path=contract_db_path)
        self.token_utils = TokenUtils(web3_provider_url)
        logger.info("SwapAnalyzer initialized", network=network, provider=web3_provider_url)

    def detect_eth_usdc_swap(self, tx_hash: str, timeout_seconds=30, use_concolic=True) -> Dict[str, Any]:
        """
        Detect if a transaction contains an ETH/USDC swap using multiple methods.

        Args:
            tx_hash: The transaction hash to analyze.
            timeout_seconds: Timeout for the concolic analysis part.
            use_concolic: Whether to perform the deeper concolic analysis if quick checks fail.

        Returns:
            A dictionary containing the analysis result, including 'is_swap' boolean
            and 'details' dictionary.
        """
        start_time = time.time()
        logger.info("Starting ETH/USDC swap detection", tx_hash=tx_hash, use_concolic=use_concolic)

        # Basic transaction validation
        if not is_hex(tx_hash) or len(tx_hash) != 66:
             logger.error("Invalid transaction hash format", tx_hash=tx_hash)
             return self._format_analysis_result(tx_hash, start_time, False, error="Invalid transaction hash format")

        try:
            # 1. Get Transaction Details
            tx = self.web3.eth.get_transaction(tx_hash)
            if not tx:
                raise TransactionNotFound(f"Transaction not found: {tx_hash}")
            tx = dict(tx) # Convert AttributeDict

            # 2. Quick Check: Method Signature and Target Address
            quick_check = self._quick_signature_check(tx)
            if quick_check["is_swap"]:
                logger.info("Swap detected via quick signature check", tx_hash=tx_hash, details=quick_check)
                return self._format_analysis_result(tx_hash, start_time, True, swap_details=quick_check)

            # 3. Quick Check: Event Logs from Receipt
            receipt = self.web3.eth.get_transaction_receipt(tx_hash)
            if not receipt:
                 # Should not happen if tx exists, but handle defensively
                 raise ValueError(f"Receipt not found for existing transaction: {tx_hash}")
            receipt = dict(receipt) # Convert AttributeDict

            # Check transaction status from receipt
            if receipt.get('status') == 0:
                 logger.info("Transaction reverted, skipping swap analysis.", tx_hash=tx_hash)
                 return self._format_analysis_result(tx_hash, start_time, True, is_swap=False, reason="Transaction reverted")

            logs_check = self._check_logs_for_swap(receipt)
            if logs_check["is_swap"]:
                logger.info("Swap detected via event logs", tx_hash=tx_hash, details=logs_check)
                return self._format_analysis_result(tx_hash, start_time, True, swap_details=logs_check)

            # 4. Deeper Analysis: Concolic Execution (if enabled)
            if use_concolic:
                logger.info("Performing concolic analysis as quick checks were inconclusive", tx_hash=tx_hash)
                # Pass timeout adjusted for time already spent, cast to int
                remaining_timeout = max(1, int(timeout_seconds - (time.time() - start_time)))
                concolic_result = self.concolic_executor.analyze_transaction(
                    tx_hash, timeout_seconds=remaining_timeout
                )
                # Re-format the result from concolic executor to match this function's output structure
                return self._format_analysis_result(
                    tx_hash,
                    start_time,
                    concolic_result.get("analysis_complete", False),
                    is_swap=concolic_result.get("is_swap", False),
                    swap_details=concolic_result.get("swap_details", {}),
                    reason="Concolic analysis result",
                    error=concolic_result.get("error")
                )
            else:
                logger.info("Concolic analysis disabled, swap not detected by quick checks.", tx_hash=tx_hash)
                return self._format_analysis_result(tx_hash, start_time, True, is_swap=False, reason="Quick checks negative, concolic disabled")

        except TransactionNotFound:
             logger.error("Transaction not found", tx_hash=tx_hash)
             return self._format_analysis_result(tx_hash, start_time, False, error="Transaction not found")
        except Exception as e:
            logger.exception("Unexpected error during swap analysis", tx_hash=tx_hash, error=str(e))
            return self._format_analysis_result(tx_hash, start_time, False, error=f"Unexpected analysis error: {str(e)}")


    def _format_analysis_result(self, tx_hash, start_time, complete, is_swap=False, swap_details=None, reason="", error=None):
        """Helper to format the final analysis result consistently."""
        execution_time = time.time() - start_time
        result = {
            "tx_hash": tx_hash,
            "analysis_complete": complete,
            "execution_time": round(execution_time, 3),
            "is_swap": is_swap,
            # Ensure swap_details is not None before accessing 'method'
            "detection_method": swap_details.get("method", reason) if is_swap and swap_details else reason,
            "swap_details": swap_details or {}
        }
        if error:
            result["error"] = error
        logger.info("Swap analysis finished", **result)
        return result

    def _quick_signature_check(self, tx: Dict) -> Dict[str, Any]:
        """Perform quick check based on method signature and call target"""
        input_data = tx.get("input", "0x")
        to_address = tx.get("to", "").lower()

        if not to_address or not input_data or len(input_data) < 10:
            return {"is_swap": False, "reason": "No target address or input data"}

        method_id = input_data[:10].lower()
        method_info = get_method_info(method_id)

        if not method_info:
            return {"is_swap": False, "reason": "Method ID not in known swap/transfer list"}

        # Is it a direct call to a known swap method?
        if method_info.swap_type in ["ETH_TO_TOKEN", "TOKEN_TO_ETH", "TOKEN_TO_TOKEN"]:
            # Check if the target is a known DEX router
            # This is a strong indicator.
            known_routers = [addr for name, addr in DEX_ROUTER_ADDRESSES.get(self.network, {}).items()]
            if to_address in known_routers:
                 # Try to decode path to see if it involves ETH/USDC
                 try:
                     # TODO: Implement robust path extraction using ABI
                     path = self._extract_swap_path(tx, method_info)
                     if path and is_eth_usdc_path(path, self.network):
                         return {
                             "is_swap": True,
                             "method": f"Direct call: {method_info.name} ({method_info.dex_type})",
                             "confidence": 0.95,
                             "details": {"path": path}
                         }
                     else:
                          # Known swap method to known router, but not ETH/USDC path
                          return {"is_swap": False, "reason": "Known swap method to router, but not ETH/USDC path"}
                 except Exception as e:
                     logger.warning("Failed to extract/check path for quick check", tx_hash=tx.get('hash'), method=method_info.name, error=str(e))
                     # Fallback: Assume it *could* be if we can't parse path
                     return {
                         "is_swap": True, # Potentially - needs deeper check
                         "method": f"Potential direct call: {method_info.name} ({method_info.dex_type}) - path check failed",
                         "confidence": 0.7,
                         "details": {}
                     }
            else:
                 # Known swap method, but not to a known router (could be proxy/custom)
                 return {"is_swap": False, "reason": "Known swap method, but not to known router"}

        # If it's just a transfer, it's not a swap itself
        if method_info.swap_type == "TRANSFER":
             return {"is_swap": False, "reason": "Direct call is ERC20 transfer"}

        return {"is_swap": False, "reason": "Unknown case in quick check"}


    def _check_logs_for_swap(self, receipt: Dict) -> Dict[str, Any]:
        """Check transaction logs for known Swap events involving ETH/USDC pools"""
        logs = receipt.get("logs", [])
        if not logs:
            return {"is_swap": False, "reason": "No logs in receipt"}

        for log in logs:
            log_address = log.get("address", "").lower()
            topics = log.get("topics", [])
            if not topics: continue

            topic0_hex = topics[0].hex() if isinstance(topics[0], bytes) else topics[0]
            event_info = get_event_info(topic0_hex)

            if event_info and event_info.name == "Swap":
                # Found a Swap event, check if it's from a known ETH/USDC pool
                if is_known_eth_usdc_pool(log_address, self.network):
                    # TODO: Decode log data to get amounts for more details
                    return {
                        "is_swap": True,
                        "method": f"Swap Event from known ETH/USDC Pool ({event_info.dex_type})",
                        "confidence": 0.98,
                        "details": {"pool_address": log_address}
                    }
                else:
                    # It's a swap, but maybe not ETH/USDC. Could check token0/token1 if needed.
                    # For now, only flag swaps from known ETH/USDC pools in this quick check.
                    pass # Continue checking other logs

        return {"is_swap": False, "reason": "No Swap event found from known ETH/USDC pool"}


    def _extract_swap_path(self, tx: Dict, method_info: SwapMethodSignature) -> Optional[List[str]]:
        """
        Placeholder for extracting the token swap path from input data using ABI.
        Uses evmole to decode input data based on the method signature.
        """
        input_data_hex = tx.get("input", "0x")
        if not input_data_hex or len(input_data_hex) < 10:
            logger.debug("No input data to extract path from.")
            return None

        if not method_info.signature:
            logger.warning("Method signature missing in patterns.py, cannot decode path.", method_name=method_info.name)
            return None

        input_data_bytes = to_bytes(hexstr=input_data_hex[10:]) # Get data part as bytes

        try:
            decoded_inputs = decode_function_input(method_info.signature, input_data_bytes)
            logger.debug("Decoded input data", method=method_info.name, decoded=decoded_inputs)

            # --- Handle different path representations ---

            # Case 1: Path is an explicit parameter (e.g., address[] path in Uniswap V2)
            if method_info.path_param_name and method_info.path_param_name in decoded_inputs:
                path_data = decoded_inputs[method_info.path_param_name]
                if isinstance(path_data, (list, tuple)):
                    # Ensure all elements are valid addresses
                    path_addresses = [to_checksum_address(addr) for addr in path_data if is_hex(addr)]
                    if len(path_addresses) == len(path_data): # Check if all were valid addresses
                        return path_addresses
                    else:
                        logger.warning("Invalid address found in decoded path array", path_data=path_data)
                        return None
                # Case 1b: Path is bytes (Uniswap V3 exactInput) - needs specific decoding
                elif isinstance(path_data, bytes):
                    # Uniswap V3 path encoding: address (20 bytes) | fee (3 bytes) | address (20 bytes) ...
                    decoded_v3_path = []
                    i = 0
                    while i < len(path_data):
                        if i + 20 > len(path_data): break # Avoid reading past end
                        addr_bytes = path_data[i:i+20]
                        decoded_v3_path.append(to_checksum_address(addr_bytes))
                        i += 20
                        if i + 3 <= len(path_data): # Check if there's a fee and potentially another address
                            # fee = int.from_bytes(path_data[i:i+3], 'big') # We don't need the fee here
                            i += 3
                        else:
                            break # Path ends after an address
                    return decoded_v3_path if decoded_v3_path else None

            # Case 2: Path is implicit in struct parameters (e.g., Uniswap V3 exactInputSingle)
            elif method_info.dex_type == "UNISWAP_V3" and method_info.name in ["exactInputSingle", "exactOutputSingle"]:
                 # The input is decoded as a single tuple representing the struct
                 if isinstance(decoded_inputs, tuple) and len(decoded_inputs) == 1 and isinstance(decoded_inputs[0], tuple):
                     params_struct = decoded_inputs[0]
                     # Infer path from tokenIn and tokenOut (assuming standard struct order)
                     # Example struct: (tokenIn, tokenOut, fee, recipient, deadline, amountIn, amountOutMinimum, sqrtPriceLimitX96)
                     # Indices might vary slightly based on exact signature used in patterns.py
                     try:
                         token_in = to_checksum_address(params_struct[0])
                         token_out = to_checksum_address(params_struct[1])
                         return [token_in, token_out]
                     except (IndexError, ValueError) as struct_err:
                         logger.error("Error extracting tokens from V3 single struct", method=method_info.name, struct_data=params_struct, error=struct_err)
                         return None
                 else:
                     logger.warning("Unexpected decoded structure for V3 single swap", method=method_info.name, decoded=decoded_inputs)
                     return None

            # --- Add more cases as needed ---

            else:
                logger.warning("Path parameter name not specified or not found in decoded inputs", method=method_info.name, path_param=method_info.path_param_name, decoded_keys=list(decoded_inputs.keys()) if isinstance(decoded_inputs, dict) else None)
                return None

        except Exception as e:
            # Catch potential errors from decode_function_input or subsequent processing
            logger.error("Error decoding input or extracting path", method=method_info.name, signature=method_info.signature, error=str(e))
            return None

        return None # Default if no path found
