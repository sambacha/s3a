"""Utilities for EVM operation simulation."""
import z3
from typing import Union, Tuple, Optional

def evm_add(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM addition (wrapping at 2^256)."""
    return z3.simplify(a + b)

def evm_sub(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM subtraction (wrapping at 2^256)."""
    return z3.simplify(a - b)

def evm_mul(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM multiplication (wrapping at 2^256)."""
    return z3.simplify(a * b)

def evm_div(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM division (x / 0 = 0)."""
    # Create division that returns 0 when dividing by 0
    return z3.If(b == 0, z3.BitVecVal(0, 256), z3.UDiv(a, b))

def evm_sdiv(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM signed division (x / 0 = 0)."""
    return z3.If(b == 0, z3.BitVecVal(0, 256), a / b)

def evm_mod(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM modulo (x % 0 = 0)."""
    return z3.If(b == 0, z3.BitVecVal(0, 256), z3.URem(a, b))

def evm_smod(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM signed modulo (x % 0 = 0)."""
    return z3.If(b == 0, z3.BitVecVal(0, 256), z3.SRem(a, b))

def evm_addmod(a: z3.BitVecRef, b: z3.BitVecRef, c: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM add-modulo (a + b) % c, (x % 0 = 0)."""
    return z3.If(c == 0, z3.BitVecVal(0, 256), z3.URem(a + b, c))

def evm_mulmod(a: z3.BitVecRef, b: z3.BitVecRef, c: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM mul-modulo (a * b) % c, (x % 0 = 0)."""
    return z3.If(c == 0, z3.BitVecVal(0, 256), z3.URem(a * b, c))

def evm_exp(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Perform EVM exponentiation a^b."""
    # FIXME: This is a simplified version. Z3 doesn't have a direct exponentiation for BitVec
    # For concrete values, we could calculate, but for symbolic would need to model differently
    return z3.BitVec(f"exp_{a}_{b}", 256)

def evm_lt(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Unsigned less than comparison."""
    return z3.If(z3.ULT(a, b), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def evm_gt(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Unsigned greater than comparison."""
    return z3.If(z3.UGT(a, b), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def evm_slt(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Signed less than comparison."""
    return z3.If(a < b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def evm_sgt(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Signed greater than comparison."""
    return z3.If(a > b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def evm_eq(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Equal comparison."""
    return z3.If(a == b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def evm_iszero(a: z3.BitVecRef) -> z3.BitVecRef:
    """Is zero check."""
    return z3.If(a == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def evm_and(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Bitwise AND."""
    return a & b

def evm_or(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Bitwise OR."""
    return a | b

def evm_xor(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Bitwise XOR."""
    return a ^ b

def evm_not(a: z3.BitVecRef) -> z3.BitVecRef:
    """Bitwise NOT."""
    return ~a

def evm_byte(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Get the nth byte of b, where n is a."""
    # FIXME: Simplified implementation, would need more complex expressions for a full model
    return z3.Extract(((31 - z3.Extract(4, 0, a).as_long()) * 8) + 7, 
                      (31 - z3.Extract(4, 0, a).as_long()) * 8, b)

def evm_shl(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Shift left."""
    return b << a

def evm_shr(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Logical shift right."""
    return z3.LShR(b, a)

def evm_sar(a: z3.BitVecRef, b: z3.BitVecRef) -> z3.BitVecRef:
    """Arithmetic shift right."""
    return b >> a

# FIXME: Add remaining EVM operations (keccak256, opcodes related to blockchain state, etc.)
