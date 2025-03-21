# tracer/etherscan_client.py
"""
Client for interacting with Etherscan API to retrieve contract information.
"""
import requests
import logging
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)

class EtherscanClient:
    """Interface for retrieving contract data from Etherscan API."""
    
    # Network-specific Etherscan API endpoints
    API_URLS = {
        "mainnet": "https://api.etherscan.io/api",
        "goerli": "https://api-goerli.etherscan.io/api",
        "sepolia": "https://api-sepolia.etherscan.io/api"
    }
    
    def __init__(self, api_key: str, network: str = "mainnet"):
        """
        Initialize Etherscan client with API key and network.
        """
        self.api_key = api_key
        
        if network not in self.API_URLS:
            raise ValueError(f"Unsupported network: {network}. Supported networks: {', '.join(self.API_URLS.keys())}")
        
        self.base_url = self.API_URLS[network]
    
    def get_contract_bytecode(self, address: str) -> str:
        """
        Retrieve contract bytecode from Etherscan.
        """
        params = {
            'module': 'proxy',
            'action': 'eth_getCode',
            'address': address,
            'tag': 'latest',
            'apikey': self.api_key
        }
        
        response = self._make_request(params)
        if not response or 'result' not in response:
            raise ValueError(f"Failed to get bytecode for {address}")
        
        bytecode = response['result']
        if bytecode == '0x' or not bytecode:
            raise ValueError(f"No bytecode found at address {address}")
        
        return bytecode
    
    def get_contract_abi(self, address: str) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Retrieve contract ABI from Etherscan.
        
        Returns:
            Tuple containing (ABI, is_verified)
        export ETHERSCAN_API_KEY=6VP5QTRB29Y2A31FDUK4GCMD31B1M51FQC

        """
        params = {
            'module': 'contract',
            'action': 'getabi',
            'address': address,
            'apikey': self.api_key
        }
        
        response = self._make_request(params)
        if not response:
            return [], False
        
        # Check if contract is verified
        if response.get('status') == '0' and 'not verified' in response.get('result', '').lower():
            logger.warning(f"Contract at {address} is not verified on Etherscan")
            return [], False
        
        try:
            import json
            abi = json.loads(response.get('result', '[]'))
            return abi, True
        except Exception as e:
            logger.error(f"Error parsing ABI: {e}")
            return [], False
    
    def get_contract_source(self, address: str) -> Dict[str, Any]:
        """
        Get contract source code and metadata from Etherscan.
        """
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': self.api_key
        }
        
        response = self._make_request(params)
        if not response or 'result' not in response or not response['result']:
            return {}
        
        return response['result'][0]
    
    def _make_request(self, params: Dict[str, str]) -> Dict[str, Any]:
        """
        Make a request to Etherscan API with appropriate error handling.
        """
        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Handle API rate limiting
            if data.get('status') == '0' and 'rate limit' in data.get('result', '').lower():
                logger.warning("Etherscan API rate limit reached, waiting 1 second...")
                import time
                time.sleep(1)
                return self._make_request(params)  # Retry once
                
            return data
        except requests.RequestException as e:
            logger.error(f"Etherscan API request failed: {e}")
            return {}