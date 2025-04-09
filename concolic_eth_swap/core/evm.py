# core/evm.py
# This file can contain EVM-related constants, opcode definitions,
# and helper functions if needed for the symbolic execution engine.

# Example (can be expanded later):
OPCODES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    # ... add other opcodes
    0x5B: "JUMPDEST",
    0x60: "PUSH1",
    # ...
}

# Gas costs (can be complex, depending on fork)
GAS_COSTS = {
    "STOP": 0,
    "ADD": 3,
    "MUL": 5,
    # ...
}


def get_opcode_info(opcode_val: int) -> str:
    return OPCODES.get(opcode_val, f"UNKNOWN_OPCODE_{hex(opcode_val)}")
