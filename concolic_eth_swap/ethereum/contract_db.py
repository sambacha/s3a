# ethereum/contract_db.py
from typing import Dict, Any, Optional, List
import structlog
import json
import os

# Placeholder for an external ABI source client (e.g., Etherscan)
# from ..utils.etherscan_client import EtherscanClient # Assuming this exists

logger = structlog.get_logger()


class ContractDB:
    """
     A simple database for storing and retrieving contract information,
     like ABIs or known interface types. Optionally fetches from external sources.
     """

    def __init__(self, db_path: Optional[str] = None, etherscan_api_key: Optional[str] = None):
        self.db_path = db_path
        self.contracts: Dict[
            str, Dict[str, Any]
        ] = {}  # address -> {abi: ..., name: ...}
        self.etherscan_client = None
        # if etherscan_api_key:
        #     try:
        #         # self.etherscan_client = EtherscanClient(api_key=etherscan_api_key)
        #         logger.info("Etherscan client initialized (placeholder).")
        #     except Exception as e:
        #         logger.error("Failed to initialize Etherscan client (placeholder)", error=str(e))
        # else:
        #     logger.info("Etherscan API key not provided, external fetching disabled.")

        if db_path and os.path.exists(db_path):
            self._load_db()

    def _load_db(self):
        """Loads contract data from a JSON file."""
        if not self.db_path:
            return
        logger.info("Loading contract database", path=self.db_path)
        try:
            with open(self.db_path, "r") as f:
                self.contracts = json.load(f)
            logger.info(f"Loaded {len(self.contracts)} contracts from database.")
        except FileNotFoundError:
            logger.warning(
                "Contract database file not found, starting fresh.", path=self.db_path
            )
            self.contracts = {}
        except json.JSONDecodeError:
            logger.exception(
                "Error decoding contract database JSON.", path=self.db_path
            )
            self.contracts = {}  # Start fresh on error
        except Exception as e:
            logger.exception(
                "Failed to load contract database", path=self.db_path, error=str(e)
            )
            self.contracts = {}

    def _save_db(self):
        """Saves the current contract data to the JSON file."""
        if not self.db_path:
            logger.warning("No database path configured, cannot save.")
            return

        logger.info(
            "Saving contract database", path=self.db_path, count=len(self.contracts)
        )
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, "w") as f:
                json.dump(self.contracts, f, indent=2)
        except Exception as e:
            logger.exception(
                "Failed to save contract database", path=self.db_path, error=str(e)
            )

    def add_contract(
        self,
        address: str,
        abi: Optional[List[Dict]] = None,
        name: Optional[str] = None,
        overwrite: bool = False,
    ):
        """Adds or updates contract information."""
        address_lower = address.lower()
        if address_lower in self.contracts and not overwrite:
            logger.debug(
                "Contract already exists, skipping add.", address=address_lower
            )
            return

        logger.debug("Adding/updating contract info", address=address_lower, name=name)
        self.contracts[address_lower] = {
            "abi": abi
            or self.contracts.get(address_lower, {}).get(
                "abi"
            ),  # Keep old ABI if new one isn't provided
            "name": name or self.contracts.get(address_lower, {}).get("name"),
            # Add other metadata fields as needed (e.g., source code link, tags)
        }
        # Optionally save immediately or batch saves
        # self._save_db()

    def get_contract_abi(self, address: str) -> Optional[List[Dict]]:
        """Retrieves the ABI for a given contract address."""
        address_lower = address.lower()
        abi = self.contracts.get(address_lower, {}).get("abi")
        if abi:
            logger.debug("Found ABI in DB", address=address_lower)
        else:
            logger.debug("ABI not found in DB, checking external sources...", address=address_lower)
            # TODO: Optionally try fetching from Etherscan or other sources here?
            if self.etherscan_client:
                try:
                    # fetched_abi = self.etherscan_client.get_abi(address_lower)
                    fetched_abi = None # Placeholder call
                    if fetched_abi:
                        logger.info("Fetched ABI from external source", address=address_lower)
                        # Optionally add to local DB for caching
                        self.add_contract(address_lower, abi=fetched_abi, overwrite=False)
                        self._save_db() # Save cache
                        return fetched_abi
                    else:
                        logger.debug("ABI not found via external source", address=address_lower)
                except Exception as e:
                    logger.error("Error fetching ABI from external source", address=address_lower, error=str(e))
            else:
                logger.debug("External ABI fetching disabled or client not available.")

        return abi # Return None if not found locally or externally

    def get_contract_name(self, address: str) -> Optional[str]:
        """Retrieves the name for a given contract address."""
        address_lower = address.lower()
        return self.contracts.get(address_lower, {}).get("name")


# Example usage (optional)
if __name__ == "__main__":
    # Example: Use a file in a 'data' subdirectory
    script_dir = os.path.dirname(__file__)
    db_file = os.path.join(
        script_dir, "..", "..", "data", "contract_db.json"
    )  # Adjust path as needed

    db = ContractDB(db_path=db_file)

    # Example: Add Uniswap V2 Router ABI (replace with actual ABI)
    uniswap_v2_addr = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
    uniswap_v2_abi_placeholder = [
        {"type": "function", "name": "swapExactETHForTokens", "inputs": [...]}
    ]  # Placeholder

    if not db.get_contract_abi(uniswap_v2_addr):
        print(f"Adding Uniswap V2 Router ({uniswap_v2_addr}) to DB...")
        db.add_contract(
            uniswap_v2_addr, abi=uniswap_v2_abi_placeholder, name="Uniswap V2 Router"
        )
        db._save_db()  # Save after adding
    else:
        print(f"Uniswap V2 Router ({uniswap_v2_addr}) already in DB.")

    # Retrieve ABI
    retrieved_abi = db.get_contract_abi(uniswap_v2_addr)
    if retrieved_abi:
        print(
            f"Retrieved ABI for {db.get_contract_name(uniswap_v2_addr)} (first element): {retrieved_abi[0]}"
        )
