# swap_detection/analyzer.py
import time  # Import time module

# swap_detection/analyzer.py
import time  # Import time module
from typing import Dict, List, Any, Tuple, Optional
import structlog
from web3 import Web3
from web3.exceptions import TransactionNotFound

# Import necessary abi and utils functions
from eth_abi import decode as abi_decode
from eth_abi.grammar import parse as parse_abi_signature
from eth_utils import (
    function_signature_to_4byte_selector,
    is_hex,
    to_checksum_address,
    to_bytes,
)
import re  # For parsing signature types

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
    DEX_ROUTER_ADDRESSES,  # Import DEX_ROUTER_ADDRESSES
)

# Assuming ContractDB might be useful here, though not explicitly used yet
from ..ethereum.contract_db import ContractDB

# Assuming TokenUtils might be useful
from ..ethereum.token_utils import TokenUtils


logger = structlog.get_logger()


class SwapAnalyzer:
    def __init__(
        self,
        web3_provider_url: str,
        network: str = "mainnet",
        contract_db_path: Optional[str] = None,
    ):
        self.concolic_executor = ConcolicExecutor(web3_provider_url, network)
        # Keep a direct web3 instance for quick checks (receipts, basic tx info)
        self.web3 = Web3(Web3.HTTPProvider(web3_provider_url))
        if not self.web3.is_connected():
            raise ConnectionError(
                f"Failed to connect to Web3 provider at {web3_provider_url}"
            )
        self.network = network
        self.contract_db = ContractDB(db_path=contract_db_path)
        self.token_utils = TokenUtils(web3_provider_url)
        logger.info(
            "SwapAnalyzer initialized", network=network, provider=web3_provider_url
        )

    def detect_eth_usdc_swap(
        self, tx_hash: str, timeout_seconds=30, use_concolic=True
    ) -> Dict[str, Any]:
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
        logger.info(
            "Starting ETH/USDC swap detection",
            tx_hash=tx_hash,
            use_concolic=use_concolic,
        )

        # Basic transaction validation
        if not is_hex(tx_hash) or len(tx_hash) != 66:
            logger.error("Invalid transaction hash format", tx_hash=tx_hash)
            return self._format_analysis_result(
                tx_hash, start_time, False, error="Invalid transaction hash format"
            )

        try:
            # 1. Get Transaction Details
            tx = self.web3.eth.get_transaction(tx_hash)
            if not tx:
                raise TransactionNotFound(f"Transaction not found: {tx_hash}")
            tx = dict(tx)  # Convert AttributeDict

            # 2. Quick Check: Method Signature and Target Address
            quick_check = self._quick_signature_check(tx)
            if quick_check["is_swap"]:
                logger.info(
                    "Swap detected via quick signature check",
                    tx_hash=tx_hash,
                    details=quick_check,
                )
                return self._format_analysis_result(
                    tx_hash, start_time, True, swap_details=quick_check
                )

            # 3. Quick Check: Event Logs from Receipt
            receipt = self.web3.eth.get_transaction_receipt(tx_hash)
            if not receipt:
                # Should not happen if tx exists, but handle defensively
                raise ValueError(
                    f"Receipt not found for existing transaction: {tx_hash}"
                )
            receipt = dict(receipt)  # Convert AttributeDict

            # Check transaction status from receipt
            if receipt.get("status") == 0:
                logger.info(
                    "Transaction reverted, skipping swap analysis.", tx_hash=tx_hash
                )
                return self._format_analysis_result(
                    tx_hash,
                    start_time,
                    True,
                    is_swap=False,
                    reason="Transaction reverted",
                )

            logs_check = self._check_logs_for_swap(receipt)
            if logs_check["is_swap"]:
                logger.info(
                    "Swap detected via event logs", tx_hash=tx_hash, details=logs_check
                )
                return self._format_analysis_result(
                    tx_hash, start_time, True, swap_details=logs_check
                )

            # 4. Deeper Analysis: Concolic Execution (if enabled)
            if use_concolic:
                logger.info(
                    "Performing concolic analysis as quick checks were inconclusive",
                    tx_hash=tx_hash,
                )
                # Pass timeout adjusted for time already spent, cast to int
                remaining_timeout = max(
                    1, int(timeout_seconds - (time.time() - start_time))
                )
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
                    error=concolic_result.get("error"),
                )
            else:
                logger.info(
                    "Concolic analysis disabled, swap not detected by quick checks.",
                    tx_hash=tx_hash,
                )
                return self._format_analysis_result(
                    tx_hash,
                    start_time,
                    True,
                    is_swap=False,
                    reason="Quick checks negative, concolic disabled",
                )

        except TransactionNotFound:
            logger.error("Transaction not found", tx_hash=tx_hash)
            return self._format_analysis_result(
                tx_hash, start_time, False, error="Transaction not found"
            )
        except Exception as e:
            logger.exception(
                "Unexpected error during swap analysis", tx_hash=tx_hash, error=str(e)
            )
            return self._format_analysis_result(
                tx_hash, start_time, False, error=f"Unexpected analysis error: {str(e)}"
            )

    def _format_analysis_result(
        self,
        tx_hash,
        start_time,
        complete,
        is_swap=False,
        swap_details=None,
        reason="",
        error=None,
    ):
        """Helper to format the final analysis result consistently."""
        execution_time = time.time() - start_time
        result = {
            "tx_hash": tx_hash,
            "analysis_complete": complete,
            "execution_time": round(execution_time, 3),
            "is_swap": is_swap,
            # Ensure swap_details is not None before accessing 'method'
            "detection_method": swap_details.get("method", reason)
            if is_swap and swap_details
            else reason,
            "swap_details": swap_details or {},
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
            return {
                "is_swap": False,
                "reason": "Method ID not in known swap/transfer list",
            }

        # Is it a direct call to a known swap method?
        if method_info.swap_type in ["ETH_TO_TOKEN", "TOKEN_TO_ETH", "TOKEN_TO_TOKEN"]:
            # Check if the target is a known DEX router
            # This is a strong indicator.
            known_routers = [
                addr
                for name, addr in DEX_ROUTER_ADDRESSES.get(self.network, {}).items()
            ]
            if to_address in known_routers:
                # Try to decode path to see if it involves ETH/USDC
                try:
                    # Path extraction is handled by _extract_swap_path
                    path = self._extract_swap_path(tx, method_info)
                    if path and is_eth_usdc_path(path, self.network):
                        return {
                            "is_swap": True,
                            "method": f"Direct call: {method_info.name} ({method_info.dex_type})",
                            "confidence": 0.95,
                            "details": {"path": path},
                        }
                    else:
                        # Known swap method to known router, but not ETH/USDC path
                        return {
                            "is_swap": False,
                            "reason": "Known swap method to router, but not ETH/USDC path",
                        }
                except Exception as e:
                    logger.warning(
                        "Failed to extract/check path for quick check",
                        tx_hash=tx.get("hash"),
                        method=method_info.name,
                        error=str(e),
                    )
                    # Fallback: Assume it *could* be if we can't parse path
                    return {
                        "is_swap": True,  # Potentially - needs deeper check
                        "method": f"Potential direct call: {method_info.name} ({method_info.dex_type}) - path check failed",
                        "confidence": 0.7,
                        "details": {},
                    }
            else:
                # Known swap method, but not to a known router (could be proxy/custom)
                return {
                    "is_swap": False,
                    "reason": "Known swap method, but not to known router",
                }

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
            if not topics:
                continue

            topic0_hex = topics[0].hex() if isinstance(topics[0], bytes) else topics[0]
            event_info = get_event_info(topic0_hex)

            if event_info and event_info.name == "Swap":
                # Found a Swap event, check if it's from a known ETH/USDC pool
                if is_known_eth_usdc_pool(log_address, self.network):
                    # Decode log data to get amounts
                    log_details = {"pool_address": log_address}
                    try:
                        data_bytes = to_bytes(hexstr=log.get("data", "0x"))
                        if event_info.dex_type == "UNISWAP_V2":
                            # V2 Swap: (uint amount0In, uint amount1In, uint amount0Out, uint amount1Out)
                            decoded_data = abi_decode(
                                ["uint256"] * 4, data_bytes
                            )
                            log_details.update({
                                "amount0In": str(decoded_data[0]),
                                "amount1In": str(decoded_data[1]),
                                "amount0Out": str(decoded_data[2]),
                                "amount1Out": str(decoded_data[3]),
                            })
                        elif event_info.dex_type == "UNISWAP_V3":
                            # V3 Swap: (int amount0, int amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick)
                            # Note: amount0/amount1 are signed integers representing change
                            decoded_data = abi_decode(
                                ["int256", "int256", "uint160", "uint128", "int24"], data_bytes
                            )
                            log_details.update({
                                "amount0Change": str(decoded_data[0]),
                                "amount1Change": str(decoded_data[1]),
                                # Optionally add sqrtPriceX96, liquidity, tick if needed
                            })
                        logger.debug("Decoded Swap event data", details=log_details)
                    except Exception as decode_err:
                        logger.warning("Failed to decode Swap event data", log_index=log.get("logIndex"), error=decode_err)

                    return {
                        "is_swap": True,
                        "method": f"Swap Event from known ETH/USDC Pool ({event_info.dex_type})",
                        "confidence": 0.98,
                        "details": {"pool_address": log_address},
                    }
                else:
                    # It's a swap, but maybe not ETH/USDC. Could check token0/token1 if needed.
                    # For now, only flag swaps from known ETH/USDC pools in this quick check.
                    pass  # Continue checking other logs

        return {
            "is_swap": False,
            "reason": "No Swap event found from known ETH/USDC pool",
        }

    def _extract_swap_path(
        self, tx: Dict, method_info: SwapMethodSignature
    ) -> Optional[List[str]]:
        """
        Extracts the token swap path from input data using eth_abi.
        Handles standard address arrays and Uniswap V3 packed byte paths.
        """
        input_data_hex = tx.get("input", "0x")
        if not input_data_hex or len(input_data_hex) < 10:
            logger.debug("No input data to extract path from.")
            return None

        if not method_info.signature:
            logger.warning(
                "Method signature missing in patterns.py, cannot decode path.",
                method_name=method_info.name,
            )
            return None

        input_data_bytes = to_bytes(
            hexstr=input_data_hex[10:]
        )  # Get data part as bytes

        try:
            # Extract types from the signature string, e.g., "swap(uint256,address[])" -> ['uint256', 'address[]']
            match = re.match(r"^[a-zA-Z0-9_]+\((.*)\)$", method_info.signature)
            if not match:
                raise ValueError(
                    f"Could not parse types from signature: {method_info.signature}"
                )
            types_string = match.group(1)
            # Use eth_abi's grammar parser to handle complex types like tuples
            parsed_types = [
                str(t) for t in parse_abi_signature(f"({types_string})")
            ]  # Wrap in tuple for parser

            decoded_inputs = abi_decode(parsed_types, input_data_bytes)
            logger.debug(
                "Decoded input data with eth-abi",
                method=method_info.name,
                types=parsed_types,
                decoded_count=len(decoded_inputs),
            )

            # --- Find the path parameter ---
            # We need to know the *index* or *name* of the path parameter.
            # Let's assume path_param_name in patterns.py tells us the name.
            # If not, we might need to infer based on type 'address[]' or 'bytes'.

            path_data = None
            if method_info.path_param_name:
                # If param names were part of the signature parsing (not standard ABI string),
                # we could potentially get them by name. But eth_abi.decode returns a tuple.
                # We need to find the index corresponding to the name.
                # This requires parsing the signature *with names*.
                # Simplified approach: Find the first argument of type address[] or bytes.
                path_index = -1
                param_names = []  # Placeholder if we could get names
                try:
                    # Attempt to parse names (this is non-standard for simple signatures)
                    # A full ABI JSON would be better here.
                    sig_parts = re.match(
                        r"^[a-zA-Z0-9_]+\((.*)\)$", method_info.signature
                    )
                    if sig_parts:
                        params_str = sig_parts.group(1)
                        # Very basic split, doesn't handle nested tuples well
                        param_defs = [p.strip() for p in params_str.split(",")]
                        param_names = [
                            p.split()[-1] for p in param_defs if len(p.split()) > 1
                        ]

                    if method_info.path_param_name in param_names:
                        path_index = param_names.index(method_info.path_param_name)
                    else:
                        # Fallback: find by type
                        for i, p_type in enumerate(parsed_types):
                            if p_type == "address[]" or p_type == "bytes":
                                path_index = i
                                break
                except Exception as parse_err:
                    logger.warning(
                        "Could not reliably determine path parameter index",
                        method=method_info.name,
                        error=parse_err,
                    )
                    # Fallback to searching by type if name/index logic fails
                    path_index = -1
                    for i, p_type in enumerate(parsed_types):
                        if p_type == "address[]" or p_type == "bytes":
                            path_index = i
                            break

                if path_index != -1 and path_index < len(decoded_inputs):
                    path_data = decoded_inputs[path_index]
                else:
                    logger.warning(
                        "Path parameter not found by name or type",
                        method=method_info.name,
                        path_param_name=method_info.path_param_name,
                        types=parsed_types,
                    )
                    return None

            # Case 2 (Implicit path in V3 Single Hop): Handled separately as path_param_name is None
            elif method_info.dex_type == "UNISWAP_V3" and method_info.name in [
                "exactInputSingle",
                "exactOutputSingle",
            ]:
                if (
                    isinstance(decoded_inputs, tuple)
                    and len(decoded_inputs) == 1
                    and isinstance(decoded_inputs[0], tuple)
                ):
                    params_struct = decoded_inputs[0]
                    try:
                        # Indices assume standard V3 struct order: (tokenIn, tokenOut, ...)
                        token_in = to_checksum_address(params_struct[0])
                        token_out = to_checksum_address(params_struct[1])
                        logger.debug(
                            "Extracted implicit path from V3 single swap",
                            method=method_info.name,
                            path=[token_in, token_out],
                        )
                        return [token_in, token_out]
                    except (IndexError, ValueError, TypeError) as struct_err:
                        logger.error(
                            "Error extracting tokens from V3 single struct",
                            method=method_info.name,
                            struct_data=params_struct,
                            error=struct_err,
                        )
                        return None
                else:
                    logger.warning(
                        "Unexpected decoded structure for V3 single swap",
                        method=method_info.name,
                        decoded=decoded_inputs,
                    )
                    return None

            # --- Process the extracted path_data ---
            if path_data is None:
                logger.warning(
                    "Path data could not be extracted", method=method_info.name
                )
                return None

            if isinstance(path_data, (list, tuple)):  # Standard address[] path
                path_addresses = [
                    to_checksum_address(addr)
                    for addr in path_data
                    if isinstance(addr, str) and is_hex(addr)
                ]
                if len(path_addresses) == len(path_data):
                    logger.debug(
                        "Extracted address[] path",
                        method=method_info.name,
                        path=path_addresses,
                    )
                    return path_addresses
                else:
                    logger.warning(
                        "Invalid address found in decoded path array",
                        path_data=path_data,
                    )
                    return None
            elif isinstance(path_data, bytes):  # Uniswap V3 packed bytes path
                decoded_v3_path = []
                i = 0
                while i < len(path_data):
                    if i + 20 > len(path_data):
                        break
                    addr_bytes = path_data[i : i + 20]
                    decoded_v3_path.append(to_checksum_address(addr_bytes))
                    i += 20
                    if i + 3 <= len(path_data):  # Skip fee
                        i += 3
                    else:
                        break  # Path ends after an address
                logger.debug(
                    "Extracted V3 bytes path",
                    method=method_info.name,
                    path=decoded_v3_path,
                )
                return decoded_v3_path if decoded_v3_path else None
            else:
                logger.warning(
                    "Extracted path data has unexpected type",
                    method=method_info.name,
                    type=type(path_data),
                )
                return None

        except Exception as e:
            logger.exception(
                "Error decoding input or extracting path with eth-abi",
                method=method_info.name,
                signature=method_info.signature,
                error=str(e),
            )
            return None
