# swap_detection/patterns.py
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
import re
import structlog

logger = structlog.get_logger()


@dataclass
class SwapMethodSignature:
    """Definition of a swap method signature pattern"""

    method_id: str  # 4-byte method signature (hex string, e.g., "0x...")
    name: str  # Human-readable name
    signature: str  # Full function signature string, e.g., "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
    # Optional: Keep simplified positions for quick checks or specific logic if needed
    # token_positions: List[int]
    # amount_positions: List[int]
    swap_type: str  # ETH_TO_TOKEN, TOKEN_TO_ETH, TOKEN_TO_TOKEN, TRANSFER
    dex_type: str  # UNISWAP_V2, UNISWAP_V3, SUSHISWAP, ERC20, etc.
    path_param_name: Optional[str] = (
        None  # Name of the 'path' parameter in the signature, if applicable
    )


@dataclass
class SwapEventSignature:
    """Definition of a swap event signature pattern"""

    topic0: str  # Event signature hash (hex string, e.g., "0x...")
    name: str  # Human-readable name
    # Positions relative to data or indexed topics. ABI decoding needed.
    token_positions: Dict[str, int]  # Placeholder: Mapping param name to position
    amount_positions: Dict[str, int]  # Placeholder: Mapping param name to position
    dex_type: str  # UNISWAP_V2, UNISWAP_V3, SUSHISWAP, etc.


# --- Known Signatures and Addresses ---
# TODO: Consider loading these from a config file (YAML/JSON) for easier updates.

# Method Signatures (with full signature strings)
UNISWAP_V2_SWAP_METHODS = [
    SwapMethodSignature(
        method_id="0x38ed1739",
        name="swapExactTokensForTokens",
        signature="swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        path_param_name="path",
        swap_type="TOKEN_TO_TOKEN",
        dex_type="UNISWAP_V2",
    ),
    SwapMethodSignature(
        method_id="0x7ff36ab5",
        name="swapExactETHForTokens",
        signature="swapExactETHForTokens(uint256,address[],address,uint256)",
        path_param_name="path",
        swap_type="ETH_TO_TOKEN",
        dex_type="UNISWAP_V2",
    ),
    SwapMethodSignature(
        method_id="0x18cbafe5",
        name="swapExactTokensForETH",
        signature="swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        path_param_name="path",
        swap_type="TOKEN_TO_ETH",
        dex_type="UNISWAP_V2",
    ),
    SwapMethodSignature(
        method_id="0x5f575529",
        name="swapExactTokensForTokensSupportingFeeOnTransferTokens",
        signature="swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
        path_param_name="path",
        swap_type="TOKEN_TO_TOKEN",
        dex_type="UNISWAP_V2",
    ),
    SwapMethodSignature(
        method_id="0xfb3bdb41",
        name="swapETHForExactTokens",
        signature="swapETHForExactTokens(uint256,address[],address,uint256)",
        path_param_name="path",
        swap_type="ETH_TO_TOKEN",
        dex_type="UNISWAP_V2",
    ),
    SwapMethodSignature(
        method_id="0xb6f9de95",
        name="swapExactTokensForETHSupportingFeeOnTransferTokens",
        signature="swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
        path_param_name="path",
        swap_type="TOKEN_TO_ETH",
        dex_type="UNISWAP_V2",
    ),
    # Add other Uniswap V2 methods...
]

UNISWAP_V3_SWAP_METHODS = [
    SwapMethodSignature(
        method_id="0x414bf389",
        name="exactInputSingle",
        signature="exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
        path_param_name=None,  # Path is implicit in tokenIn/tokenOut within the struct
        swap_type="TOKEN_TO_TOKEN",
        dex_type="UNISWAP_V3",
    ),
    SwapMethodSignature(
        method_id="0xc04b8d59",
        name="exactInput",
        signature="exactInput((bytes,address,uint256,uint256,uint160))",
        path_param_name="path",  # Path is bytes, needs special decoding
        swap_type="TOKEN_TO_TOKEN",
        dex_type="UNISWAP_V3",
    ),
    SwapMethodSignature(
        method_id="0x5ae401dc",
        name="exactOutputSingle",
        signature="exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
        path_param_name=None,  # Path implicit in tokenIn/tokenOut
        swap_type="TOKEN_TO_TOKEN",
        dex_type="UNISWAP_V3",
    ),
    SwapMethodSignature(
        method_id="0x09b81346",
        name="exactOutput",
        signature="exactOutput((bytes,address,uint256,uint256,uint160))",
        path_param_name="path",  # Path is bytes
        swap_type="TOKEN_TO_TOKEN",
        dex_type="UNISWAP_V3",
    ),
    # Add other Uniswap V3 methods...
]

TOKEN_TRANSFER_METHODS = [
    SwapMethodSignature(
        method_id="0xa9059cbb",
        name="transfer",
        signature="transfer(address,uint256)",
        path_param_name=None,
        swap_type="TRANSFER",
        dex_type="ERC20",
    ),
    SwapMethodSignature(
        method_id="0x23b872dd",
        name="transferFrom",
        signature="transferFrom(address,address,uint256)",
        path_param_name=None,
        swap_type="TRANSFER",
        dex_type="ERC20",
    ),
]

ALL_SWAP_METHODS = UNISWAP_V2_SWAP_METHODS + UNISWAP_V3_SWAP_METHODS
ALL_METHODS = ALL_SWAP_METHODS + TOKEN_TRANSFER_METHODS

# Event Signatures
SWAP_EVENTS = [
    SwapEventSignature(
        topic0="0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",
        name="Swap",  # Uniswap V2 Pair Swap
        token_positions={},
        amount_positions={
            "amount0In": 1,
            "amount1In": 2,
            "amount0Out": 3,
            "amount1Out": 4,
        },  # In data part
        dex_type="UNISWAP_V2",
    ),
    SwapEventSignature(
        topic0="0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67",
        name="Swap",  # Uniswap V3 Pool Swap
        token_positions={},
        amount_positions={
            "amount0": 1,
            "amount1": 2,
        },  # In data part, sqrtPriceX96 etc also present
        dex_type="UNISWAP_V3",
    ),
    # Add other relevant events (e.g., Sync for V2, Mint/Burn for V3 liquidity) if needed
]

# Token Addresses (Lowercase for consistent comparison)
TOKEN_ADDRESSES = {
    "mainnet": {
        "WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
    },
    "goerli": {
        "WETH": "0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6",
        "USDC": "0x07865c6e87b9f70255377e024ace6630c1eaa37f",
        # Add other testnet tokens...
    },
    # Add other networks like sepolia, polygon, etc.
}

# DEX Router Addresses (Lowercase)
DEX_ROUTER_ADDRESSES = {
    "mainnet": {
        "UNISWAP_V2": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
        "UNISWAP_V3": "0xe592427a0aece92de3edee1f18e0157c05861564",
        "SUSHISWAP": "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f",
        # Add other mainnet DEX routers...
    },
    "goerli": {
        "UNISWAP_V2": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
        "UNISWAP_V3": "0xe592427a0aece92de3edee1f18e0157c05861564",
        # Add other testnet DEX routers...
    },
    # Add other networks
}

# Known ETH/USDC Pool Addresses (Lowercase) - For quick log checks
# This is fragile; ideally, check token0/token1 from the contract state.
KNOWN_ETH_USDC_POOLS = {
    "mainnet": {
        # Uniswap V2 ETH/USDC pool
        "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc": "UNISWAP_V2",
        # Uniswap V3 ETH/USDC 0.05% pool
        "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640": "UNISWAP_V3",
        # Uniswap V3 ETH/USDC 0.3% pool
        "0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8": "UNISWAP_V3",
        # Uniswap V3 ETH/USDC 1% pool
        "0x7bea39867e4169dbe237d55c8242a8f2fcdcc387": "UNISWAP_V3",
        # Add other known ETH/USDC pools (SushiSwap, etc.)
    },
    "goerli": {
        # Add known Goerli pools if needed
    },
}


# --- Helper Functions ---


def get_token_address(symbol: str, network: str = "mainnet") -> Optional[str]:
    """Get the address of a token by symbol for a given network."""
    return TOKEN_ADDRESSES.get(network, {}).get(symbol)


def get_dex_router_address(dex_name: str, network: str = "mainnet") -> Optional[str]:
    """Get the address of a DEX router by name for a given network."""
    return DEX_ROUTER_ADDRESSES.get(network, {}).get(dex_name)


def is_eth_usdc_path(path: List[str], network: str = "mainnet") -> bool:
    """
    Determine if a token path represents an ETH/USDC swap (directly or indirectly).
    Assumes WETH represents ETH in paths.
    """
    if not path or len(path) < 2:
        return False

    addresses = TOKEN_ADDRESSES.get(network, TOKEN_ADDRESSES.get("mainnet", {}))
    weth_addr = addresses.get("WETH")
    usdc_addr = addresses.get("USDC")

    if not weth_addr or not usdc_addr:
        logger.warning("WETH or USDC address not found for network", network=network)
        return False

    path_lower = [addr.lower() for addr in path]
    weth_addr_lower = weth_addr.lower()
    usdc_addr_lower = usdc_addr.lower()

    # Check start and end of the path
    start_is_eth_or_usdc = path_lower[0] in [weth_addr_lower, usdc_addr_lower]
    end_is_eth_or_usdc = path_lower[-1] in [weth_addr_lower, usdc_addr_lower]

    # Ensure start and end are different (ETH -> USDC or USDC -> ETH)
    if start_is_eth_or_usdc and end_is_eth_or_usdc and path_lower[0] != path_lower[-1]:
        logger.debug("Detected ETH/USDC path", path=path, network=network)
        return True

    return False


def get_method_info(method_id: str) -> Optional[SwapMethodSignature]:
    """Get method information for a given method ID."""
    method_id_lower = method_id.lower()
    for method in ALL_METHODS:
        if method.method_id.lower() == method_id_lower:
            return method
    return None


def get_event_info(topic0: str) -> Optional[SwapEventSignature]:
    """Get event information for a given topic0 hash."""
    topic0_lower = topic0.lower()
    for event in SWAP_EVENTS:
        if event.topic0.lower() == topic0_lower:
            return event
    return None


def is_known_eth_usdc_pool(pool_address: str, network: str = "mainnet") -> bool:
    """Check if a pool address is a known ETH/USDC pool for the network."""
    return pool_address.lower() in KNOWN_ETH_USDC_POOLS.get(network, {})
