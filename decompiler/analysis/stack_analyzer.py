# Mapping from opcode name to (pops, pushes)
# Based on https://www.evm.codes/
OPCODE_STACK_EFFECTS = {
    # 0s: Stop and Arithmetic Operations
    "STOP": (0, 0),
    "ADD": (2, 1),
    "MUL": (2, 1),
    "SUB": (2, 1),
    "DIV": (2, 1),
    "SDIV": (2, 1),
    "MOD": (2, 1),
    "SMOD": (2, 1),
    "ADDMOD": (3, 1),
    "MULMOD": (3, 1),
    "EXP": (2, 1),
    "SIGNEXTEND": (2, 1),
    # 10s: Comparison & Bitwise Logic Operations
    "LT": (2, 1),
    "GT": (2, 1),
    "SLT": (2, 1),
    "SGT": (2, 1),
    "EQ": (2, 1),
    "ISZERO": (1, 1),
    "AND": (2, 1),
    "OR": (2, 1),
    "XOR": (2, 1),
    "NOT": (1, 1),
    "BYTE": (2, 1),
    "SHL": (2, 1),
    "SHR": (2, 1),
    "SAR": (2, 1),
    # 20s: Keccak256
    "KECCAK256": (2, 1),  # Previously SHA3
    # 30s: Environmental Information
    "ADDRESS": (0, 1),
    "BALANCE": (1, 1),
    "ORIGIN": (0, 1),
    "CALLER": (0, 1),
    "CALLVALUE": (0, 1),
    "CALLDATALOAD": (1, 1),
    "CALLDATASIZE": (0, 1),
    "CALLDATACOPY": (3, 0),
    "CODESIZE": (0, 1),
    "CODECOPY": (3, 0),
    "GASPRICE": (0, 1),
    "EXTCODESIZE": (1, 1),
    "EXTCODECOPY": (4, 0),
    "RETURNDATASIZE": (0, 1),
    "RETURNDATACOPY": (3, 0),
    "EXTCODEHASH": (1, 1),
    # 40s: Block Information
    "BLOCKHASH": (1, 1),
    "COINBASE": (0, 1),
    "TIMESTAMP": (0, 1),
    "NUMBER": (0, 1),
    "DIFFICULTY": (0, 1),  # PREVRANDAO post-merge
    "GASLIMIT": (0, 1),
    "CHAINID": (0, 1),
    "SELFBALANCE": (
        0,
        1,
    ),  # SELFBALANCE takes 0 args since EIP-1884, but older docs might say 1
    "BASEFEE": (0, 1),  # EIP-3198
    # 50s: Stack, Memory, Storage and Flow Operations
    "POP": (1, 0),
    "MLOAD": (1, 1),
    "MSTORE": (2, 0),
    "MSTORE8": (2, 0),
    "SLOAD": (1, 1),
    "SSTORE": (2, 0),
    "JUMP": (1, 0),
    "JUMPI": (2, 0),
    "PC": (0, 1),
    "MSIZE": (0, 1),
    "GAS": (0, 1),
    "JUMPDEST": (0, 0),
    # 60s & 70s: Push Operations
    # Handled separately
    # 80s: Duplication Operations
    # Handled separately
    # 90s: Exchange Operations
    # Handled separately
    # a0s: Logging Operations
    "LOG0": (2, 0),
    "LOG1": (3, 0),
    "LOG2": (4, 0),
    "LOG3": (5, 0),
    "LOG4": (6, 0),
    # f0s: System operations
    "CREATE": (3, 1),
    "CALL": (7, 1),
    "CALLCODE": (7, 1),
    "RETURN": (2, 0),
    "DELEGATECALL": (6, 1),
    "CREATE2": (4, 1),
    "STATICCALL": (6, 1),
    "REVERT": (2, 0),
    "INVALID": (0, 0),  # Defined as 0xff
    "SELFDESTRUCT": (1, 0),
}


def analyze_stack_locally(block):
    """
    Analyze stack effects within a single basic block.
    Tracks which values are pushed onto the stack and
    which operations consume stack values. Uses explicit pops/pushes per opcode.
    """
    stack_height = 0  # Simulate height change, not actual values
    total_pushes = 0
    total_pops = 0
    min_height = 0  # Track minimum height to estimate input stack height needed

    # Assume block.stack_height_in is unknown initially
    # We calculate the effect relative to the start of the block

    for instr in block.instructions:
        opcode = instr.opcode
        pops, pushes = 0, 0

        if opcode.startswith("PUSH"):
            pops, pushes = 0, 1
        elif opcode.startswith("DUP"):
            # DUPn pops 0, pushes 1. Needs n items on stack.
            dup_n = int(opcode[3:])
            pops, pushes = 0, 1
            if stack_height < dup_n:
                min_height = min(min_height, stack_height - dup_n)
        elif opcode.startswith("SWAP"):
            # SWAPn pops 0, pushes 0. Needs n+1 items on stack.
            swap_n = int(opcode[4:])
            pops, pushes = 0, 0
            if stack_height < swap_n + 1:
                min_height = min(min_height, stack_height - (swap_n + 1))
        elif opcode in OPCODE_STACK_EFFECTS:
            pops, pushes = OPCODE_STACK_EFFECTS[opcode]
        else:
            # Unknown opcode, assume 0 effect? Or handle as error?
            # For now, assume 0,0 but log?
            # print(f"Warning: Unknown opcode {opcode} encountered in stack analysis")
            pops, pushes = 0, 0

        # Check for potential stack underflow based on pops
        if stack_height < pops:
            min_height = min(min_height, stack_height - pops)

        # Update simulated height
        stack_height -= pops
        stack_height += pushes

        # Update totals
        total_pops += pops
        total_pushes += pushes

    # The required input height is the negation of the minimum height reached (if negative)
    block.stack_height_in = max(0, -min_height)
    # The output height is the final simulated height relative to the input height
    block.stack_height_out = block.stack_height_in + stack_height
    # The stack effect is the total pushes and pops
    block.stack_effect = (total_pushes, total_pops)
