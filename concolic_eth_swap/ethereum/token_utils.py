# ethereum/token_utils.py
from typing import Dict, Any, Optional, List, Union
import structlog
from web3 import Web3
from web3.exceptions import ContractLogicError

logger = structlog.get_logger()

# Standard ERC20 ABI subset needed for balance and metadata
ERC20_ABI_MINIMAL = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
]


class TokenUtils:
    def __init__(self, web3_provider_url: str):
        self.web3 = Web3(Web3.HTTPProvider(web3_provider_url))
        if not self.web3.is_connected():
            raise ConnectionError(
                f"Failed to connect to Web3 provider at {web3_provider_url}"
            )
        # Cache for token metadata
        self.token_metadata_cache: Dict[
            str, Dict[str, Any]
        ] = {}  # address -> {symbol, name, decimals}

    def get_token_balance(
        self,
        token_address: str,
        user_address: str,
        block_identifier: Optional[Union[str, int]] = "latest",
    ) -> Optional[int]:
        """
        Retrieves the ERC20 token balance for a user at a specific block.

        Returns:
            The balance as an integer, or None if an error occurs.
        """
        logger.debug(
            "Fetching token balance",
            token=token_address,
            user=user_address,
            block=block_identifier,
        )
        try:
            token_contract = self.web3.eth.contract(
                address=token_address, abi=ERC20_ABI_MINIMAL
            )
            balance = token_contract.functions.balanceOf(user_address).call(
                block_identifier=block_identifier
            )
            return balance
        except ContractLogicError as cle:
            # Contract logic errors (e.g., revert) might indicate non-ERC20 or other issues
            logger.warning(
                "Contract logic error fetching balance",
                token=token_address,
                user=user_address,
                error=str(cle),
            )
            return None
        except Exception as e:
            # Catch other potential errors (e.g., connection issues, invalid address format)
            logger.exception(
                "Error fetching token balance",
                token=token_address,
                user=user_address,
                block=block_identifier,
                error=str(e),
            )
            return None

    def get_token_metadata(
        self, token_address: str, use_cache: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves metadata (symbol, name, decimals) for an ERC20 token.
        """
        address_lower = token_address.lower()
        if use_cache and address_lower in self.token_metadata_cache:
            logger.debug("Returning cached token metadata", token=token_address)
            return self.token_metadata_cache[address_lower]

        logger.debug("Fetching token metadata", token=token_address)
        try:
            token_contract = self.web3.eth.contract(
                address=token_address, abi=ERC20_ABI_MINIMAL
            )
            # Use multicall or batch requests in a real scenario for efficiency
            symbol = token_contract.functions.symbol().call()
            name = token_contract.functions.name().call()
            decimals = token_contract.functions.decimals().call()

            metadata = {"symbol": symbol, "name": name, "decimals": decimals}
            self.token_metadata_cache[address_lower] = metadata  # Update cache
            return metadata
        except ContractLogicError as cle:
            logger.warning(
                "Contract logic error fetching metadata (maybe not ERC20?)",
                token=token_address,
                error=str(cle),
            )
            return None
        except Exception as e:
            logger.exception(
                "Error fetching token metadata", token=token_address, error=str(e)
            )
            return None

    def format_balance(self, balance: int, decimals: int) -> str:
        """Formats a raw token balance using its decimals."""
        if decimals == 0:
            return str(balance)
        factor = 10**decimals
        integer_part = balance // factor
        fractional_part = balance % factor
        return f"{integer_part}.{fractional_part:0{decimals}d}"  # Pad fractional part with leading zeros


# Example usage (optional)
if __name__ == "__main__":
    provider = "http://localhost:8545"  # Replace with your provider
    token_utils = TokenUtils(provider)

    # Example: Get USDC balance (replace addresses)
    usdc_address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"  # Mainnet USDC
    user_address = "0x..."  # Replace with an address holding USDC

    try:
        metadata = token_utils.get_token_metadata(usdc_address)
        if metadata:
            print(f"Token Metadata ({usdc_address}): {metadata}")
            balance = token_utils.get_token_balance(usdc_address, user_address)
            if balance is not None:
                formatted = token_utils.format_balance(balance, metadata["decimals"])
                print(f"Balance of {user_address}: {formatted} {metadata['symbol']}")
            else:
                print(f"Could not retrieve balance for {user_address}")
        else:
            print(f"Could not retrieve metadata for {usdc_address}")

    except ConnectionError as ce:
        print(f"Connection failed: {ce}")
    except Exception as ex:
        print(f"An error occurred: {ex}")
