#!/usr/bin/env python3
"""
Unified CLI for EVM storage layout analysis.

This module provides a single entry point for analyzing Ethereum smart contract
storage layouts using symbolic execution with Z3 SMT solver.
"""

import argparse
import json
import os
import subprocess
import time
import logging
import sys
from typing import Dict, List, Optional, Tuple, Any, Union
from pathlib import Path
from web3 import Web3
from web3.types import ABI

from tracer.storage_analyzer import StorageAnalyzer
from tracer.etherscan_client import EtherscanClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_RPC_URLS = {
    "mainnet": "https://ethereum.publicnode.com",
    "goerli": "https://ethereum-goerli.publicnode.com",
    "sepolia": "https://ethereum-sepolia.publicnode.com", 
    "local": "http://localhost:8545"
}
DEFAULT_GAS_LIMIT = 2_000_000
DEFAULT_OUTPUT_DIR = "build"
DEFAULT_RESULTS_DIR = "results"
DEFAULT_MAX_EXECUTION_PATHS = 200  # Increased from 100 to improve coverage

# Anvil default private key (for development only)
ANVIL_DEFAULT_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def load_from_artifact(file_path: str, contract_name: Optional[str] = None) -> Tuple[ABI, str]:
    """
    Load contract ABI and bytecode from a compiled artifact file.
    
    Supports various artifact formats including:
    - solc combined.json
    - Hardhat/Truffle artifacts
    - Foundry artifacts
    
    Args:
        file_path: Path to the artifact file
        contract_name: Specific contract to load (uses first contract if None)
        
    Returns:
        Tuple containing (ABI, bytecode)
        
    Raises:
        FileNotFoundError: If the artifact file doesn't exist
        ValueError: If the artifact format is unrecognized or contract not found
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Artifact file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        artifact = json.load(f)
    
    # Handle standard solc combined.json format
    if "contracts" in artifact:
        contracts = artifact["contracts"]
        
        # Find target contract
        if contract_name:
            target_contract = None
            for key in contracts:
                if key.endswith(f":{contract_name}") or key.endswith(f"/{contract_name}"):
                    target_contract = contracts[key]
                    logger.info(f"Found contract {contract_name} in {key}")
                    break
            
            if not target_contract:
                raise ValueError(f"Contract {contract_name} not found in compilation artifact")
        else:
            # Use first contract if no name specified
            contract_key = next(iter(contracts))
            target_contract = contracts[contract_key]
            logger.info(f"Using first contract: {contract_key}")
        
        # Extract ABI and bytecode
        abi = json.loads(target_contract["abi"]) if isinstance(target_contract["abi"], str) else target_contract["abi"]
        bytecode = "0x" + target_contract["bin"] if "bin" in target_contract else target_contract.get("bytecode", "")
        
        return abi, bytecode
    
    # Handle Hardhat/Truffle artifact format
    elif all(k in artifact for k in ["abi", "bytecode"]):
        return artifact["abi"], artifact["bytecode"]
    
    # Handle Foundry artifact format
    elif "abi" in artifact and ("bytecode" in artifact.get("deployedBytecode", {}) or "object" in artifact.get("bytecode", {})):
        abi = artifact["abi"]
        bytecode = artifact.get("bytecode", {}).get("object", "")
        if not bytecode:
            bytecode = artifact.get("deployedBytecode", {}).get("bytecode", "")
        
        if not bytecode.startswith("0x"):
            bytecode = "0x" + bytecode
            
        return abi, bytecode
    
    raise ValueError("Unrecognized compilation artifact format")


def compile_contract(contract_path: str, output_dir: str = DEFAULT_OUTPUT_DIR) -> Tuple[ABI, str]:
    """
    Compile a Solidity contract using the solc compiler.
    
    Args:
        contract_path: Path to the Solidity contract
        output_dir: Directory to store compiled output
        
    Returns:
        Tuple containing (ABI, bytecode)
        
    Raises:
        FileNotFoundError: If the contract or solc is not found
        subprocess.CalledProcessError: If compilation fails
        ValueError: If compiled output cannot be found
    """
    logger.info(f"Compiling contract: {contract_path}")
    
    # Validate inputs
    contract_path = os.path.abspath(contract_path)
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contract file not found: {contract_path}")
    
    # Create output directory
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    # Run solc compiler
    try:
        solc_cmd = [
            "solc",
            "--combined-json", "abi,bin",
            "--optimize",
            "--overwrite",
            "--output-dir", output_dir,
            contract_path
        ]
        
        result = subprocess.run(
            solc_cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        # Parse the output
        combined_json_path = os.path.join(output_dir, "combined.json")
        
        if os.path.exists(combined_json_path):
            contract_name = os.path.basename(contract_path).split('.')[0]
            return load_from_artifact(combined_json_path, contract_name)
        
        # Fallback to individual output files
        contract_name = os.path.basename(contract_path).split('.')[0]
        abi_path = os.path.join(output_dir, f"{contract_name}.abi")
        bin_path = os.path.join(output_dir, f"{contract_name}.bin")
        
        if os.path.exists(abi_path) and os.path.exists(bin_path):
            with open(abi_path, 'r') as f:
                abi = json.load(f)
            with open(bin_path, 'r') as f:
                bytecode = "0x" + f.read().strip()
            return abi, bytecode
        
        raise ValueError(f"Could not find compiled outputs for {contract_path}")
        
    except FileNotFoundError:
        logger.error("Solidity compiler (solc) not found. Please install solc.")
        raise
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Compilation failed: {e.stderr}")
        raise


def get_contract_from_etherscan(address: str, api_key: str, network: str = "mainnet") -> Tuple[str, Optional[ABI]]:
    """
    Retrieve contract bytecode and ABI from Etherscan.
    
    Args:
        address: Contract address
        api_key: Etherscan API key
        network: Ethereum network (mainnet, goerli, sepolia)
        
    Returns:
        Tuple containing (bytecode, ABI or None if not verified)
        
    Raises:
        ValueError: If the contract doesn't exist or API key is invalid
    """
    logger.info(f"Getting contract information from Etherscan for {address} on {network}")
    
    etherscan = EtherscanClient(api_key, network)
    
    # Get bytecode (this will throw if contract doesn't exist)
    bytecode = etherscan.get_contract_bytecode(address)
    logger.info(f"Retrieved bytecode of size: {len(bytecode) // 2} bytes")
    
    # Try to get ABI if contract is verified
    abi, is_verified = etherscan.get_contract_abi(address)
    
    if is_verified:
        logger.info("Contract is verified on Etherscan, retrieved ABI")
        
        # Get additional contract info for context
        contract_info = etherscan.get_contract_source(address)
        if contract_info:
            logger.info(f"Contract name: {contract_info.get('ContractName', 'Unknown')}")
            logger.info(f"Compiler version: {contract_info.get('CompilerVersion', 'Unknown')}")
    else:
        logger.warning("Contract is not verified on Etherscan, no ABI available")
        abi = None
    
    return bytecode, abi


def start_anvil(port: int = 8545) -> subprocess.Popen:
    """
    Start a local Anvil Ethereum node for testing.
    
    Args:
        port: Port to run Anvil on
        
    Returns:
        Subprocess object for the Anvil process
        
    Raises:
        FileNotFoundError: If Anvil is not installed
        RuntimeError: If Anvil fails to start
    """
    logger.info(f"Starting Anvil local Ethereum node on port {port}...")
    try:
        anvil_process = subprocess.Popen(
            ["anvil", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for Anvil to start
        time.sleep(2)
        
        # Check if the process is running
        if anvil_process.poll() is not None:
            stderr = anvil_process.stderr.read() if anvil_process.stderr else "Unknown error"
            raise RuntimeError(f"Anvil failed to start: {stderr}")
        
        logger.info("Anvil started successfully")
        return anvil_process
    
    except FileNotFoundError:
        logger.error("Anvil not found. Install Foundry from https://getfoundry.sh/")
        raise


def connect_to_ethereum(rpc_url: str, retries: int = 3, retry_delay: int = 2) -> Web3:
    """
    Establish a connection to an Ethereum node with retry logic.
    
    Args:
        rpc_url: RPC URL for the Ethereum node
        retries: Number of connection attempts
        retry_delay: Delay between retries in seconds
        
    Returns:
        Web3 instance
        
    Raises:
        ConnectionError: If connection fails after all retries
    """
    logger.info(f"Connecting to Ethereum node at {rpc_url}...")
    
    for attempt in range(retries):
        try:
            # Create Web3 instance
            web3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 30}))
            
            # Check connection
            if web3.is_connected():
                logger.info(f"Connected to Ethereum node at {rpc_url}")
                return web3
            
            logger.warning(f"Failed to connect to {rpc_url} (attempt {attempt+1}/{retries})")
            
        except Exception as e:
            logger.warning(f"Error connecting to {rpc_url}: {str(e)} (attempt {attempt+1}/{retries})")
        
        # Wait before retrying
        if attempt < retries - 1:
            time.sleep(retry_delay)
    
    raise ConnectionError(f"Could not connect to Ethereum node at {rpc_url} after {retries} attempts")


def deploy_contract(
    web3: Web3, 
    abi: ABI, 
    bytecode: str, 
    constructor_args: List[Any] = None,
    gas_limit: int = DEFAULT_GAS_LIMIT
) -> str:
    """
    Deploy a contract to the connected Ethereum network.
    
    Args:
        web3: Web3 instance
        abi: Contract ABI
        bytecode: Contract bytecode
        constructor_args: List of constructor arguments
        gas_limit: Gas limit for the deployment transaction
        
    Returns:
        Deployed contract address
        
    Raises:
        ValueError: If deployment fails
    """
    logger.info("Deploying contract...")
    
    # Get default account
    if not web3.eth.accounts:
        raise ValueError("No accounts available for deployment")
    
    account = web3.eth.accounts[0]
    
    # Use private key for local development with Anvil
    private_key = ANVIL_DEFAULT_PRIVATE_KEY
    
    # Create contract instance
    contract = web3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Prepare constructor transaction
    constructor_args = constructor_args or []
    
    try:
        # Build transaction
        construct_txn = contract.constructor(*constructor_args).build_transaction({
            'from': account,
            'nonce': web3.eth.get_transaction_count(account),
            'gas': gas_limit,
            'gasPrice': web3.eth.gas_price
        })
        
        # Sign and send transaction
        signed_txn = web3.eth.account.sign_transaction(construct_txn, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"Deployment transaction sent: {web3.to_hex(tx_hash)}")
        
        # Wait for transaction receipt
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress
        
        logger.info(f"Contract deployed at: {contract_address}")
        return contract_address
    
    except Exception as e:
        logger.error(f"Contract deployment failed: {str(e)}")
        raise ValueError(f"Contract deployment failed: {str(e)}")


def analyze_bytecode(
    bytecode: str,
    max_execution_paths: int = DEFAULT_MAX_EXECUTION_PATHS
) -> Tuple[str, Dict[str, Any]]:
    """
    Analyze contract bytecode to detect storage layout.
    
    Args:
        bytecode: Contract bytecode
        max_execution_paths: Maximum number of execution paths to explore
        
    Returns:
        Tuple of (string representation, dictionary representation)
        
    Raises:
        ValueError: If analysis fails
    """
    logger.info(f"Analyzing bytecode of size: {len(bytecode) // 2} bytes")
    
    # Create storage analyzer with appropriate settings
    analyzer = StorageAnalyzer(max_execution_paths=max_execution_paths)
    
    # Analyze bytecode
    layout = analyzer.analyze(bytecode)
    
    # Return both string and dictionary representations
    layout_str = str(layout)
    layout_dict = layout.to_dict()
    
    return layout_str, layout_dict


def analyze_contract(
    web3: Web3, 
    contract_address: str,
    max_execution_paths: int = DEFAULT_MAX_EXECUTION_PATHS
) -> Tuple[str, Dict[str, Any]]:
    """
    Analyze a deployed contract's storage layout.
    
    Args:
        web3: Web3 instance
        contract_address: Contract address
        max_execution_paths: Maximum number of execution paths to explore
        
    Returns:
        Tuple of (string representation, dictionary representation)
        
    Raises:
        ValueError: If analysis fails
    """
    logger.info(f"Analyzing contract at {contract_address}...")
    
    try:
        # Get contract bytecode
        bytecode = web3.eth.get_code(contract_address).hex()
        if bytecode == "0x" or not bytecode:
            raise ValueError(f"No bytecode found at address {contract_address}")
        
        # Use the bytecode analyzer
        return analyze_bytecode(bytecode, max_execution_paths)
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise


def save_results(
    layout_dict: Dict[str, Any],
    contract_address: str,
    output_dir: str = DEFAULT_RESULTS_DIR
) -> str:
    """
    Save analysis results to a JSON file.
    
    Args:
        layout_dict: Dictionary representation of the layout
        contract_address: Contract address
        output_dir: Directory to save results
        
    Returns:
        Path to the saved file
        
    Raises:
        IOError: If the file cannot be written
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Create filename with contract address and timestamp
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.join(output_dir, f"storage-layout-{contract_address}-{timestamp}.json")
    
    # Save to file
    try:
        with open(filename, 'w') as f:
            json.dump(layout_dict, f, indent=2)
        
        logger.info(f"Results saved to {filename}")
        return filename
    
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        raise


def main() -> int:
    """
    Parse arguments and run the appropriate commands based on user input.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        description="EVM Storage Layout Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Contract source options (choose one)
    contract_group = parser.add_argument_group("Contract Source Options (choose one)")
    contract_group.add_argument(
        "--contract", 
        help="Path to the Solidity contract file"
    )
    
    contract_group.add_argument(
        "--artifact",
        help="Path to a compiled contract artifact (combined.json, etc.)"
    )
    
    contract_group.add_argument(
        "--address", 
        help="Contract address to analyze (if already deployed)"
    )
    
    contract_group.add_argument(
        "--bytecode",
        help="Raw bytecode to analyze (as hex string)"
    )
    
    # Artifact options
    parser.add_argument(
        "--contract-name",
        help="Name of the contract in the artifact (if multiple contracts exist)"
    )
    
    # Network options
    parser.add_argument(
        "--network",
        choices=["mainnet", "goerli", "sepolia", "local"],
        default="local",
        help="Ethereum network to use"
    )
    
    parser.add_argument(
        "--rpc-url", 
        help="Custom RPC URL for Ethereum node"
    )
    
    parser.add_argument(
        "--etherscan-key",
        help="Etherscan API key for retrieving contract information"
    )
    
    parser.add_argument(
        "--anvil", 
        action="store_true", 
        help="Start Anvil node for testing"
    )
    
    parser.add_argument(
        "--anvil-port",
        type=int,
        default=8545,
        help="Port to run Anvil on"
    )
    
    # Analysis options
    parser.add_argument(
        "--gas-limit",
        type=int,
        help="Gas limit for contract deployment",
        default=DEFAULT_GAS_LIMIT
    )
    
    parser.add_argument(
        "--max-paths",
        type=int,
        help="Maximum number of execution paths to explore",
        default=DEFAULT_MAX_EXECUTION_PATHS
    )
    
    parser.add_argument(
        "--output-dir",
        help="Directory to save results",
        default=DEFAULT_RESULTS_DIR
    )
    
    parser.add_argument(
        "--constructor-args",
        nargs="+",
        help="Constructor arguments for contract deployment",
        default=["TestContract"]
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input options
    source_options = [args.contract, args.artifact, args.address, args.bytecode]
    if sum(1 for opt in source_options if opt) != 1:
        parser.error("Exactly one of --contract, --artifact, --address, or --bytecode must be specified")
    
    # Check for required Etherscan API key when using non-local networks
    if args.network != "local" and args.address and not args.etherscan_key:
        parser.error("--etherscan-key is required when analyzing contracts on public networks")
    
    anvil_process = None
    
    try:
        # Direct bytecode analysis
        if args.bytecode:
            logger.info("Analyzing raw bytecode...")
            bytecode = args.bytecode
            if not bytecode.startswith("0x"):
                bytecode = "0x" + bytecode
                
            layout_str, layout_dict = analyze_bytecode(
                bytecode,
                max_execution_paths=args.max_paths
            )
            
            # Save and display results
            save_results(layout_dict, "raw_bytecode", args.output_dir)
            
            print("\nStorage Layout Analysis Result:")
            print("===============================")
            print(layout_str)
            
            return 0
        
        # Handle Etherscan integration for public networks
        if args.address and args.network != "local" and args.etherscan_key:
            bytecode, abi = get_contract_from_etherscan(args.address, args.etherscan_key, args.network)
            
            # Analyze bytecode directly
            layout_str, layout_dict = analyze_bytecode(
                bytecode,
                max_execution_paths=args.max_paths
            )
            
            # Save and display results
            save_results(layout_dict, args.address, args.output_dir)
            
            print("\nStorage Layout Analysis Result:")
            print("===============================")
            print(layout_str)
            
            return 0
        
        # Start Anvil if requested for local testing
        if args.anvil:
            anvil_process = start_anvil(args.anvil_port)
        
        # Determine RPC URL
        rpc_url = args.rpc_url or DEFAULT_RPC_URLS.get(args.network)
        
        # Connect to Ethereum node
        web3 = connect_to_ethereum(rpc_url)
        
        # Get contract address
        contract_address = args.address
        if not contract_address:
            # Get contract ABI and bytecode
            if args.artifact:
                # Load from artifact
                abi, bytecode = load_from_artifact(args.artifact, args.contract_name)
            elif args.contract:
                # Compile the contract
                abi, bytecode = compile_contract(args.contract)
            else:
                raise ValueError("No contract source specified")
            
            # Deploy the contract
            contract_address = deploy_contract(
                web3, 
                abi, 
                bytecode, 
                constructor_args=args.constructor_args,
                gas_limit=args.gas_limit
            )
        
        # Analyze contract
        layout_str, layout_dict = analyze_contract(
            web3, 
            contract_address,
            max_execution_paths=args.max_paths
        )
        
        # Save results
        save_results(layout_dict, contract_address, args.output_dir)
        
        # Print results
        print("\nStorage Layout Analysis Result:")
        print("===============================")
        print(layout_str)
        
        return 0  # Success
        
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return 130  # Standard exit code for Ctrl+C
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1  # Error
        
    finally:
        # Clean up Anvil process if we started it
        if anvil_process:
            logger.info("Stopping Anvil...")
            anvil_process.terminate()
            try:
                anvil_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                anvil_process.kill()
                anvil_process.wait()


if __name__ == "__main__":
    sys.exit(main())
