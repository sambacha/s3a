#!/usr/bin/env python3
"""
BLSSS State Structure Exporter

This script creates a sample symbolic state structure as used in the
Branchless Lockless Symbolic State Storage (BLSSS) system and exports
it to a file in various formats (JSON, YAML, or diagram-friendly format).

Usage:
    python blsss_state_exporter.py --format json --output state_structure.json
"""

import json
import yaml
import argparse
import os
import z3
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class Z3ExprWrapper:
    """Wrapper for Z3 expressions to make them serializable"""
    expr_str: str
    expr_type: str
    expr_sort: str

    @classmethod
    def from_expr(cls, expr: z3.ExprRef) -> 'Z3ExprWrapper':
        """Create a wrapper from a Z3 expression"""
        return cls(
            expr_str=str(expr),
            expr_type=str(type(expr)),
            expr_sort=str(expr.sort())
        )


@dataclass
class Balance:
    """Container for ETH/USDC balances"""
    eth: Z3ExprWrapper
    usdc: Z3ExprWrapper
    
    @classmethod
    def create(cls, ctx: z3.Context, prefix: str = "") -> 'Balance':
        """Create a new balance with Z3 expressions"""
        return cls(
            eth=Z3ExprWrapper.from_expr(ctx.bv_const(f"{prefix}eth", 256)),
            usdc=Z3ExprWrapper.from_expr(ctx.bv_const(f"{prefix}usdc", 256))
        )


@dataclass
class TokenBalances:
    """Container for token balances in symbolic state"""
    sender: Balance
    contract: Balance
    
    @classmethod
    def create(cls, ctx: z3.Context) -> 'TokenBalances':
        """Create a new token balances object with Z3 expressions"""
        return cls(
            sender=Balance.create(ctx, "sender_"),
            contract=Balance.create(ctx, "contract_")
        )


@dataclass
class MemoryAccess:
    """Represents an EVM memory operation"""
    address: Z3ExprWrapper
    value: Z3ExprWrapper
    is_read: bool
    
    @classmethod
    def create(cls, ctx: z3.Context, addr_name: str, val_name: str, is_read: bool) -> 'MemoryAccess':
        """Create a new memory access with Z3 expressions"""
        return cls(
            address=Z3ExprWrapper.from_expr(ctx.bv_const(addr_name, 256)),
            value=Z3ExprWrapper.from_expr(ctx.bv_const(val_name, 256)),
            is_read=is_read
        )


@dataclass
class SymbolicState:
    """
    Container for symbolic execution state.
    
    Represents a complete state during symbolic execution, including:
    - Path constraints: Logical conditions that must be true on this execution path
    - Variables: Mapping of variable names to their symbolic expressions
    - Memory accesses: History of memory operations performed
    - Depth: Current execution depth in the symbolic tree
    - Token balances: ETH/USDC token balances for swap detection
    """
    path_constraints: List[Z3ExprWrapper] = field(default_factory=list)
    variables: Dict[str, Z3ExprWrapper] = field(default_factory=dict)
    memory_accesses: List[MemoryAccess] = field(default_factory=list)
    depth: int = 0
    token_balances: Optional[TokenBalances] = None
    
    @classmethod
    def create_sample(cls, ctx: z3.Context) -> 'SymbolicState':
        """Create a sample symbolic state for demonstration"""
        state = cls(depth=2)
        
        # Add variables
        x = ctx.int_const("x")
        y = ctx.int_const("y")
        z = ctx.int_const("z")
        state.variables["x"] = Z3ExprWrapper.from_expr(x)
        state.variables["y"] = Z3ExprWrapper.from_expr(y)
        state.variables["z"] = Z3ExprWrapper.from_expr(z)
        
        # Add constraints
        state.path_constraints.append(Z3ExprWrapper.from_expr(x > 0))
        state.path_constraints.append(Z3ExprWrapper.from_expr(y > x))
        state.path_constraints.append(Z3ExprWrapper.from_expr(z == x + y))
        state.path_constraints.append(Z3ExprWrapper.from_expr(z < 100))
        
        # Add memory accesses
        state.memory_accesses.append(
            MemoryAccess.create(ctx, "addr1", "val1", True)
        )
        state.memory_accesses.append(
            MemoryAccess.create(ctx, "addr2", "val2", False)
        )
        
        # Set token balances
        state.token_balances = TokenBalances.create(ctx)
        
        return state


@dataclass
class BucketMetadata:
    """Metadata structure for a bucket in the metadata array"""
    hash_fragment: int  # 4 bytes: Memoized partial hash
    state_index: int    # 2 bytes: Index into state data array
    status: int         # 1 byte: Current bucket status
    version: int        # 1 byte: Counter to prevent ABA problem
    
    @classmethod
    def create_empty(cls) -> 'BucketMetadata':
        """Create an empty bucket metadata"""
        return cls(hash_fragment=0, state_index=0, status=0, version=0)
    
    @classmethod
    def create_sample(cls, hash_value: int, index: int) -> 'BucketMetadata':
        """Create a sample bucket metadata for demonstration"""
        return cls(hash_fragment=hash_value, state_index=index, status=2, version=1)


@dataclass
class MetadataArray:
    """Represents the array of bucket metadata entries"""
    buckets: List[BucketMetadata]
    cache_line_size: int = 64
    
    @classmethod
    def create_sample(cls, size: int = 64) -> 'MetadataArray':
        """Create a sample metadata array for demonstration"""
        # Create mostly empty buckets
        buckets = [BucketMetadata.create_empty() for _ in range(size)]
        
        # Add a few sample states
        buckets[3] = BucketMetadata.create_sample(0x12345678, 0)
        buckets[17] = BucketMetadata.create_sample(0x87654321, 1)
        buckets[42] = BucketMetadata.create_sample(0xABCDEF01, 2)
        
        return cls(buckets=buckets)


@dataclass
class BLSSSStructure:
    """Top-level structure representing the entire BLSSS system"""
    metadata_array: MetadataArray
    symbolic_states: List[SymbolicState]
    
    @classmethod
    def create_sample(cls, ctx: z3.Context) -> 'BLSSSStructure':
        """Create a sample BLSSS structure for demonstration"""
        # Create sample states
        states = [
            SymbolicState.create_sample(ctx),
            SymbolicState.create_sample(ctx),
            SymbolicState.create_sample(ctx)
        ]
        
        # Modify the second state to make it different
        states[1].depth = 3
        states[1].variables["w"] = Z3ExprWrapper.from_expr(ctx.int_const("w"))
        states[1].path_constraints.append(
            Z3ExprWrapper.from_expr(ctx.int_const("w") > 10)
        )
        
        # Modify the third state
        states[2].depth = 5
        states[2].path_constraints = [
            Z3ExprWrapper.from_expr(ctx.int_const("a") == ctx.int_const("b"))
        ]
        
        # Create metadata array referring to these states
        metadata = MetadataArray.create_sample()
        
        return cls(metadata_array=metadata, symbolic_states=states)


def export_to_json(data: Any, filename: str) -> None:
    """Export data to a JSON file"""
    with open(filename, 'w') as f:
        json.dump(asdict(data), f, indent=2)
    print(f"Structure exported to JSON: {filename}")


def export_to_yaml(data: Any, filename: str) -> None:
    """Export data to a YAML file"""
    with open(filename, 'w') as f:
        yaml.dump(asdict(data), f, default_flow_style=False)
    print(f"Structure exported to YAML: {filename}")


def export_to_diagram(data: BLSSSStructure, filename: str) -> None:
    """Export data in a format suitable for diagram generation"""
    with open(filename, 'w') as f:
        # Write header
        f.write("BLSSS Structure Diagram Data\n")
        f.write("===========================\n\n")
        
        # Write metadata array information
        f.write("Metadata Array:\n")
        f.write(f"  Size: {len(data.metadata_array.buckets)} buckets\n")
        f.write(f"  Cache Line Size: {data.metadata_array.cache_line_size} bytes\n")
        f.write(f"  Entries Per Cache Line: {data.metadata_array.cache_line_size // 8}\n\n")
        
        # Write non-empty buckets
        f.write("Non-Empty Buckets:\n")
        for i, bucket in enumerate(data.metadata_array.buckets):
            if bucket.status != 0:  # Not empty
                f.write(f"  Bucket {i}:\n")
                f.write(f"    Hash Fragment: 0x{bucket.hash_fragment:08x}\n")
                f.write(f"    State Index: {bucket.state_index}\n")
                f.write(f"    Status: {bucket.status}\n")
                f.write(f"    Version: {bucket.version}\n\n")
        
        # Write symbolic states
        f.write("Symbolic States:\n")
        for i, state in enumerate(data.symbolic_states):
            f.write(f"  State {i}:\n")
            f.write(f"    Depth: {state.depth}\n")
            f.write(f"    Variables: {', '.join(state.variables.keys())}\n")
            f.write(f"    Path Constraints: {len(state.path_constraints)}\n")
            f.write(f"    Memory Accesses: {len(state.memory_accesses)}\n\n")
        
        # Write references
        f.write("References from Metadata to States:\n")
        for i, bucket in enumerate(data.metadata_array.buckets):
            if bucket.status == 2:  # DONE status
                f.write(f"  Bucket {i} -> State {bucket.state_index}\n")
    
    print(f"Structure exported for diagram: {filename}")


def main():
    parser = argparse.ArgumentParser(description='Export BLSSS state structure to a file')
    parser.add_argument('--format', choices=['json', 'yaml', 'diagram'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('--output', default='blsss_structure.json',
                        help='Output filename (default: blsss_structure.json)')
    
    args = parser.parse_args()
    
    # Create Z3 context
    ctx = z3.Context()
    
    # Create sample BLSSS structure
    structure = BLSSSStructure.create_sample(ctx)
    
    # Export in requested format
    if args.format == 'json':
        export_to_json(structure, args.output)
    elif args.format == 'yaml':
        export_to_yaml(structure, args.output)
    elif args.format == 'diagram':
        export_to_diagram(structure, args.output)


if __name__ == "__main__":
    main()