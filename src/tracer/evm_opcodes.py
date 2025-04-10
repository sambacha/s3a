"""
EVM Opcode definitions and utilities for the symbolic tracer.
"""

from enum import IntEnum


class Opcode(IntEnum):
    """EVM Opcodes"""

    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    SDIV = 0x05
    MOD = 0x06
    SMOD = 0x07
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0A
    SIGNEXTEND = 0x0B

    LT = 0x10
    GT = 0x11
    SLT = 0x12
    SGT = 0x13
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1A
    SHL = 0x1B
    SHR = 0x1C
    SAR = 0x1D

    SHA3 = 0x20

    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3A
    EXTCODESIZE = 0x3B
    EXTCODECOPY = 0x3C
    RETURNDATASIZE = 0x3D
    RETURNDATACOPY = 0x3E
    EXTCODEHASH = 0x3F

    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    SELFBALANCE = 0x47
    BASEFEE = 0x48

    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5A
    JUMPDEST = 0x5B

    PUSH1 = 0x60
    PUSH2 = 0x61
    PUSH3 = 0x62
    PUSH4 = 0x63
    PUSH5 = 0x64
    PUSH6 = 0x65
    PUSH7 = 0x66
    PUSH8 = 0x67
    PUSH9 = 0x68
    PUSH10 = 0x69
    PUSH11 = 0x6A
    PUSH12 = 0x6B
    PUSH13 = 0x6C
    PUSH14 = 0x6D
    PUSH15 = 0x6E
    PUSH16 = 0x6F
    PUSH17 = 0x70
    PUSH18 = 0x71
    PUSH19 = 0x72
    PUSH20 = 0x73
    PUSH21 = 0x74
    PUSH22 = 0x75
    PUSH23 = 0x76
    PUSH24 = 0x77
    PUSH25 = 0x78
    PUSH26 = 0x79
    PUSH27 = 0x7A
    PUSH28 = 0x7B
    PUSH29 = 0x7C
    PUSH30 = 0x7D
    PUSH31 = 0x7E
    PUSH32 = 0x7F

    DUP1 = 0x80
    DUP2 = 0x81
    DUP3 = 0x82
    DUP4 = 0x83
    DUP5 = 0x84
    DUP6 = 0x85
    DUP7 = 0x86
    DUP8 = 0x87
    DUP9 = 0x88
    DUP10 = 0x89
    DUP11 = 0x8A
    DUP12 = 0x8B
    DUP13 = 0x8C
    DUP14 = 0x8D
    DUP15 = 0x8E
    DUP16 = 0x8F

    SWAP1 = 0x90
    SWAP2 = 0x91
    SWAP3 = 0x92
    SWAP4 = 0x93
    SWAP5 = 0x94
    SWAP6 = 0x95
    SWAP7 = 0x96
    SWAP8 = 0x97
    SWAP9 = 0x98
    SWAP10 = 0x99
    SWAP11 = 0x9A
    SWAP12 = 0x9B
    SWAP13 = 0x9C
    SWAP14 = 0x9D
    SWAP15 = 0x9E
    SWAP16 = 0x9F

    LOG0 = 0xA0
    LOG1 = 0xA1
    LOG2 = 0xA2
    LOG3 = 0xA3
    LOG4 = 0xA4

    CREATE = 0xF0
    CALL = 0xF1
    CALLCODE = 0xF2
    RETURN = 0xF3
    DELEGATECALL = 0xF4
    CREATE2 = 0xF5
    STATICCALL = 0xFA
    REVERT = 0xFD
    INVALID = 0xFE
    SELFDESTRUCT = 0xFF


# Map from opcode value to name
OPCODE_NAMES = {int(code): name for name, code in Opcode.__members__.items()}

# Map from opcode to number of bytes to read for PUSH operations
PUSH_BYTES = {Opcode.PUSH1 + i: i + 1 for i in range(32)}

# Map from opcode to stack in, stack out counts
STACK_EFFECTS = {
    # 0s arithmetic
    Opcode.STOP: (0, 0),
    Opcode.ADD: (2, 1),
    Opcode.MUL: (2, 1),
    Opcode.SUB: (2, 1),
    Opcode.DIV: (2, 1),
    Opcode.SDIV: (2, 1),
    Opcode.MOD: (2, 1),
    Opcode.SMOD: (2, 1),
    Opcode.ADDMOD: (3, 1),
    Opcode.MULMOD: (3, 1),
    Opcode.EXP: (2, 1),
    Opcode.SIGNEXTEND: (2, 1),
    # 10s comparisons
    Opcode.LT: (2, 1),
    Opcode.GT: (2, 1),
    Opcode.SLT: (2, 1),
    Opcode.SGT: (2, 1),
    Opcode.EQ: (2, 1),
    Opcode.ISZERO: (1, 1),
    Opcode.AND: (2, 1),
    Opcode.OR: (2, 1),
    Opcode.XOR: (2, 1),
    Opcode.NOT: (1, 1),
    Opcode.BYTE: (2, 1),
    Opcode.SHL: (2, 1),
    Opcode.SHR: (2, 1),
    Opcode.SAR: (2, 1),
    # 20s hashing
    Opcode.SHA3: (2, 1),
    # 30s environmental
    Opcode.ADDRESS: (0, 1),
    Opcode.BALANCE: (1, 1),
    Opcode.ORIGIN: (0, 1),
    Opcode.CALLER: (0, 1),
    Opcode.CALLVALUE: (0, 1),
    Opcode.CALLDATALOAD: (1, 1),
    Opcode.CALLDATASIZE: (0, 1),
    Opcode.CALLDATACOPY: (3, 0),
    Opcode.CODESIZE: (0, 1),
    Opcode.CODECOPY: (3, 0),
    Opcode.GASPRICE: (0, 1),
    Opcode.EXTCODESIZE: (1, 1),
    Opcode.EXTCODECOPY: (4, 0),
    Opcode.RETURNDATASIZE: (0, 1),
    Opcode.RETURNDATACOPY: (3, 0),
    Opcode.EXTCODEHASH: (1, 1),
    # 40s block info
    Opcode.BLOCKHASH: (1, 1),
    Opcode.COINBASE: (0, 1),
    Opcode.TIMESTAMP: (0, 1),
    Opcode.NUMBER: (0, 1),
    Opcode.DIFFICULTY: (0, 1),
    Opcode.GASLIMIT: (0, 1),
    Opcode.CHAINID: (0, 1),
    Opcode.SELFBALANCE: (0, 1),
    Opcode.BASEFEE: (0, 1),
    # 50s stack, memory, storage, flow
    Opcode.POP: (1, 0),
    Opcode.MLOAD: (1, 1),
    Opcode.MSTORE: (2, 0),
    Opcode.MSTORE8: (2, 0),
    Opcode.SLOAD: (1, 1),
    Opcode.SSTORE: (2, 0),
    Opcode.JUMP: (1, 0),
    Opcode.JUMPI: (2, 0),
    Opcode.PC: (0, 1),
    Opcode.MSIZE: (0, 1),
    Opcode.GAS: (0, 1),
    Opcode.JUMPDEST: (0, 0),
    # Logs
    Opcode.LOG0: (2, 0),
    Opcode.LOG1: (3, 0),
    Opcode.LOG2: (4, 0),
    Opcode.LOG3: (5, 0),
    Opcode.LOG4: (6, 0),
    # System operations
    Opcode.CREATE: (3, 1),
    Opcode.CALL: (7, 1),
    Opcode.CALLCODE: (7, 1),
    Opcode.RETURN: (2, 0),
    Opcode.DELEGATECALL: (6, 1),
    Opcode.CREATE2: (4, 1),
    Opcode.STATICCALL: (6, 1),
    Opcode.REVERT: (2, 0),
    Opcode.INVALID: (0, 0),
    Opcode.SELFDESTRUCT: (1, 0),
}

# Add PUSH operations
for i in range(1, 33):
    STACK_EFFECTS[Opcode.PUSH1 + i - 1] = (0, 1)

# Add DUP operations
for i in range(1, 17):
    STACK_EFFECTS[Opcode.DUP1 + i - 1] = (i, i + 1)

# Add SWAP operations
for i in range(1, 17):
    STACK_EFFECTS[Opcode.SWAP1 + i - 1] = (i + 1, i + 1)


def disassemble_bytecode(bytecode):
    """
    Disassemble EVM bytecode into a list of operations.

    Args:
        bytecode: Hexadecimal string representing the bytecode

    Returns:
        List of tuples (opcode_name, opcode_value, push_data, offset)
    """
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]

    bytecode_bytes = bytes.fromhex(bytecode)
    operations = []
    i = 0

    while i < len(bytecode_bytes):
        opcode_value = bytecode_bytes[i]
        offset = i
        i += 1

        # Get opcode name
        opcode_name = OPCODE_NAMES.get(opcode_value, f"UNKNOWN_{opcode_value:02x}")

        # Handle PUSH operations
        push_data = None
        if Opcode.PUSH1 <= opcode_value <= Opcode.PUSH32:
            push_bytes = opcode_value - Opcode.PUSH1 + 1
            if i + push_bytes <= len(bytecode_bytes):
                push_data = bytecode_bytes[i : i + push_bytes]
                i += push_bytes
            else:
                # Not enough bytes for push operation
                push_data = bytecode_bytes[i:]
                i = len(bytecode_bytes)

        operations.append((opcode_name, opcode_value, push_data, offset))

    return operations


def get_stack_effect(opcode):
    """
    Get the stack effect of an opcode (how many items it pops and pushes).

    Args:
        opcode: The opcode value

    Returns:
        Tuple (stack_in, stack_out)
    """
    return STACK_EFFECTS.get(opcode, (0, 0))
