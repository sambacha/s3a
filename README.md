# SMT EVM Storage Layout Analyzer

A symbolic execution-based tool for automatically detecting storage layouts in Ethereum smart contracts. This tool uses Z3 SMT solver to analyze EVM bytecode and identify storage variables, their types, and patterns.

## Features

- **Bytecode Analysis**: Analyze raw EVM bytecode without source code
- **Storage Variable Detection**: Automatically detect storage variables and their types
- **Complex Pattern Recognition**: Identify mappings, arrays, and simple variables
- **Type Inference**: Infer variable types based on observed values and access patterns
- **Multiple Input Sources**:
  - Solidity source files (automatically compiled)
  - Compiled artifacts (combined.json, Hardhat/Truffle artifacts, Foundry artifacts)
  - Deployed contract addresses (local or public networks)
  - Raw bytecode
- **Symbolic Execution**: The bytecode is symbolically executed, tracking all storage operations (SLOAD and SSTORE).
- **Storage Pattern Detection**: Storage access patterns are analyzed to identify:
   - Simple variables (constant slot numbers)
   - Mappings (slots involving keccak256 hash operations)
   - Arrays (slots with index arithmetic)


## Example Output

```

Storage Layout Analysis Result:
===============================
Storage Layout:
----------------
Slot 0x0: value1 (uint256)
Slot 0x1: owner (address)
Slot 0x541: uint16 (uint16)
Slot 0x2: paused (bool)
Slot 0x3: smallValue1 (uint128) [offset: 0, size: 16]
Slot 0x3: smallValue2 (uint128) [offset: 16, size: 16]
Slot 0x4: balances (mapping(address => uint256))
Slot 0x5: values (uint256[])
Slot 0x231: unknown5 (unknown)
Slot 0x6: fixedValues[0] (uint256)
Slot 0x25b: unknown3 (unknown)
Slot 0x260: unknown4 (unknown)
Slot 0x297: unknown2 (unknown)
Slot 0x7: fixedValues[1] (uint256)
Slot 0x8: fixedValues[2] (uint256)
Slot 0x399: unknown (unknown)

```


### Command Line Options

```console
usage: cli.py [-h] [--contract CONTRACT] [--artifact ARTIFACT] [--address ADDRESS] [--bytecode BYTECODE] [--contract-name CONTRACT_NAME]
              [--network {mainnet,goerli,sepolia,local}] [--rpc-url RPC_URL] [--etherscan-key ETHERSCAN_KEY] [--anvil] [--anvil-port ANVIL_PORT]
              [--gas-limit GAS_LIMIT] [--max-paths MAX_PATHS] [--output-dir OUTPUT_DIR] [--constructor-args CONSTRUCTOR_ARGS [CONSTRUCTOR_ARGS ...]]
              [--verbose]

EVM Storage Layout Analyzer

options:
  -h, --help            show this help message and exit

Contract Source Options (choose one):
  --contract CONTRACT   Path to the Solidity contract file (default: None)
  --artifact ARTIFACT   Path to a compiled contract artifact (combined.json, etc.) (default: None)
  --address ADDRESS     Contract address to analyze (if already deployed) (default: None)
  --bytecode BYTECODE   Raw bytecode to analyze (as hex string) (default: None)

  --contract-name CONTRACT_NAME
                        Name of the contract in the artifact (if multiple contracts exist) (default: None)
  --network {mainnet,goerli,sepolia,local}
                        Ethereum network to use (default: local)
  --rpc-url RPC_URL     Custom RPC URL for Ethereum node (default: None)
  --etherscan-key ETHERSCAN_KEY
                        Etherscan API key for retrieving contract information (default: None)
  --anvil               Start Anvil node for testing (default: False)
  --anvil-port ANVIL_PORT
                        Port to run Anvil on (default: 8545)
  --gas-limit GAS_LIMIT
                        Gas limit for contract deployment (default: 2000000)
  --max-paths MAX_PATHS
                        Maximum number of execution paths to explore (default: 100)
  --output-dir OUTPUT_DIR
                        Directory to save results (default: results)
  --constructor-args CONSTRUCTOR_ARGS [CONSTRUCTOR_ARGS ...]
                        Constructor arguments for contract deployment (default: ['TestContract'])
  --verbose, -v         Enable verbose logging (default: False)
```

### Examples

#### Analyze a Contract on Mainnet

```bash
python main.py --address 0x617c8dE5BdE54ffbb8d92716CC947858cA38f582 --network mainnet --etherscan-key YOUR_API_KEY
```

#### Analyze Raw Bytecode

```bash
python main.py --bytecode 0x608060405234801561001057600080fd5b50...
```

#### Increase Execution Path Coverage

```bash
python main.py --contract contracts/StorageTest.sol --max-paths 200
```

## Output Format

The tool outputs a JSON file with the detected storage layout, as well as a human-readable summary to the console:

```
Storage Layout:
----------------
Slot 0x0: owner (address)
Slot 0x1: value1 (uint256)
Slot 0x2: paused (bool)
Slot 0x3: name (string)
Slot 0x4: balancesByAddress (mapping(address => uint256))
Slot 0x5: uint256Array (uint256[])
```

