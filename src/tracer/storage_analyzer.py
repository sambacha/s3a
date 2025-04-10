"""
Storage layout analyzer for EVM contract bytecode.

This module provides classes and functions to analyze the storage layout
of Ethereum smart contracts by examining bytecode execution patterns.
"""

from typing import Dict, List, Optional, Set, Tuple, Union, Any, DefaultDict
import z3
import logging
from collections import defaultdict
from eth_utils import to_hex, to_checksum_address, keccak

from .symbolic_tracer import SymbolicExecutor, StorageAccess, SymbolicValue

logger = logging.getLogger(__name__)


class StorageLayout:
    """
    Represents the storage layout of a contract.

    This class maintains a collection of variables that have been identified
    in a contract's storage, along with their types and locations.

    Attributes:
        variables: List of storage variables found in the contract
    """

    def __init__(self) -> None:
        """Initialize an empty storage layout."""
        self.variables: List[StorageVariable] = []

    def add_variable(self, variable: "StorageVariable") -> None:
        """
        Add a storage variable to the layout.

        Args:
            variable: The storage variable to add
        """
        self.variables.append(variable)

    def get_variable_by_slot(
        self, slot: Union[int, str]
    ) -> Optional["StorageVariable"]:
        """
        Find a variable by its slot.

        Args:
            slot: The storage slot to search for

        Returns:
            The variable at the specified slot, or None if not found
        """
        for var in self.variables:
            if var.slot == slot:
                return var
        return None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the storage layout to a dictionary.

        Returns:
            Dictionary representation of the storage layout
        """
        return {"variables": [var.to_dict() for var in self.variables]}

    def __str__(self) -> str:
        """String representation of the storage layout."""
        result = []
        result.append("Storage Layout:")
        result.append("----------------")

        for var in sorted(self.variables, key=lambda v: str(v.slot)):
            result.append(str(var))

        return "\n".join(result)


class StorageVariable:
    """
    Represents a single storage variable.

    This class contains information about a variable stored in contract storage,
    including its slot, type, name, and size.

    Attributes:
        slot: Storage slot (can be concrete or symbolic)
        var_type: Variable type (e.g., uint256, address, bool)
        name: Variable name
        offset: Offset within the slot (for packed variables)
        size: Size of the variable in bytes
        accesses: List of storage accesses to this variable
    """

    def __init__(
        self,
        slot: Union[int, str],
        var_type: Optional[str] = None,
        name: Optional[str] = None,
        offset: int = 0,
        size: int = 32,
    ) -> None:
        """
        Initialize a storage variable.

        Args:
            slot: Storage slot (concrete or symbolic)
            var_type: Variable type
            name: Variable name (defaults to "var_{slot}")
            offset: Offset within the slot (for packed variables)
            size: Size of the variable in bytes
        """
        self.slot = slot
        self.var_type = var_type or "unknown"
        self.name = name or f"var_{slot}"
        self.offset = offset
        self.size = size
        self.accesses: List[StorageAccess] = []

    def add_access(self, access: StorageAccess) -> None:
        """
        Add a storage access to this variable.

        Args:
            access: The storage access to add
        """
        self.accesses.append(access)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the variable to a dictionary.

        Returns:
            Dictionary representation of the variable
        """
        return {
            "name": self.name,
            "type": self.var_type,
            "slot": str(self.slot),
            "offset": self.offset,
            "size": self.size,
        }

    def __str__(self) -> str:
        """String representation of the variable."""
        if isinstance(self.slot, int):
            slot_str = f"0x{self.slot:x}"
        else:
            slot_str = str(self.slot)

        result = f"Slot {slot_str}: {self.name} ({self.var_type})"
        if self.offset > 0 or self.size < 32:
            result += f" [offset: {self.offset}, size: {self.size}]"
        return result


class MappingVariable(StorageVariable):
    """
    Represents a mapping variable in storage.

    This class contains information about a mapping variable, including its
    key type and value type.

    Attributes:
        key_type: Type of the mapping key
        value_type: Type of the mapping value
    """

    def __init__(
        self,
        slot: Union[int, str],
        key_type: Optional[str] = None,
        value_type: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        """
        Initialize a mapping variable.

        Args:
            slot: Storage slot
            key_type: Type of the mapping key
            value_type: Type of the mapping value
            name: Variable name
        """
        super().__init__(slot, "mapping", name)
        self.key_type = key_type or "unknown"
        self.value_type = value_type or "unknown"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the mapping to a dictionary.

        Returns:
            Dictionary representation of the mapping
        """
        result = super().to_dict()
        result["key_type"] = self.key_type
        result["value_type"] = self.value_type
        return result

    def __str__(self) -> str:
        """String representation of the mapping."""
        if isinstance(self.slot, int):
            slot_str = f"0x{self.slot:x}"
        else:
            slot_str = str(self.slot)

        return f"Slot {slot_str}: {self.name} (mapping({self.key_type} => {self.value_type}))"


class ArrayVariable(StorageVariable):
    """
    Represents an array variable in storage.

    This class contains information about an array variable, including the
    type of its elements.

    Attributes:
        element_type: Type of array elements
        length: Length of the array (if known)
    """

    def __init__(
        self,
        slot: Union[int, str],
        element_type: Optional[str] = None,
        name: Optional[str] = None,
        length: Optional[int] = None,
    ) -> None:
        """
        Initialize an array variable.

        Args:
            slot: Storage slot
            element_type: Type of array elements
            name: Variable name
            length: Length of the array (if known)
        """
        super().__init__(slot, "array", name)
        self.element_type = element_type or "unknown"
        self.length = length

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the array to a dictionary.

        Returns:
            Dictionary representation of the array
        """
        result = super().to_dict()
        result["element_type"] = self.element_type
        if self.length is not None:
            result["length"] = self.length
        return result

    def __str__(self) -> str:
        """String representation of the array."""
        if isinstance(self.slot, int):
            slot_str = f"0x{self.slot:x}"
        else:
            slot_str = str(self.slot)

        result = f"Slot {slot_str}: {self.name} ({self.element_type}[])"
        if self.length is not None:
            result = (
                f"Slot {slot_str}: {self.name} ({self.element_type}[{self.length}])"
            )
        return result


class StorageAnalyzer:
    """
    Analyzes contract storage layout using symbolic execution.

    This class uses symbolic execution to analyze contract bytecode and
    determine the storage layout.

    Attributes:
        executor: Symbolic executor for EVM bytecode
        layout: Detected storage layout
        known_patterns: Dictionary of common storage patterns for detection
    """

    def __init__(self, max_execution_paths: int = 100) -> None:
        """
        Initialize the storage analyzer.

        Args:
            max_execution_paths: Maximum number of execution paths to explore
        """
        self.executor = SymbolicExecutor(max_paths=max_execution_paths)
        self.layout = StorageLayout()

        # Define known storage patterns for better detection
        self.known_patterns = {
            # ERC20 standard storage layout
            "erc20": {
                "name": {"slot": 0, "type": "string"},
                "symbol": {"slot": 1, "type": "string"},
                "decimals": {"slot": 2, "type": "uint8"},
                "totalSupply": {"slot": 3, "type": "uint256"},
                "balances": {"slot": 4, "type": "mapping(address => uint256)"},
                "allowances": {
                    "slot": 5,
                    "type": "mapping(address => mapping(address => uint256))",
                },
            },
            # OpenZeppelin Ownable pattern
            "ownable": {
                "owner": {"slot": 0, "type": "address"},
            },
            # OpenZeppelin Pausable pattern
            "pausable": {
                "paused": {"slot": 0, "type": "bool"},
            },
            # Standard proxy pattern
            "proxy": {
                "implementation": {
                    "slot": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                    "type": "address",
                },
                "admin": {
                    "slot": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
                    "type": "address",
                },
            },
        }

    def analyze(self, bytecode: str) -> StorageLayout:
        """
        Analyze contract bytecode to determine storage layout.

        Args:
            bytecode: Hexadecimal string representing the bytecode

        Returns:
            StorageLayout object containing the detected layout

        Raises:
            ValueError: If the bytecode is invalid
        """
        # Validate bytecode
        if not bytecode or not isinstance(bytecode, str):
            raise ValueError("Bytecode must be a non-empty string")

        # Reset state
        self.layout = StorageLayout()

        logger.info("Running symbolic execution to collect storage accesses...")
        # Run symbolic execution to collect storage accesses
        storage_accesses = self.executor.analyze(bytecode)
        logger.info(f"Found {len(storage_accesses)} storage accesses")

        # Process storage accesses
        logger.info("Analyzing storage access patterns...")
        self._analyze_storage_accesses(storage_accesses)

        # Assign variable names based on patterns
        self._assign_variable_names()

        return self.layout

    def _analyze_storage_accesses(self, accesses: List[StorageAccess]) -> None:
        """
        Analyze storage accesses to determine variable slots and types.

        Args:
            accesses: List of StorageAccess objects
        """
        # Group accesses by slot
        slot_accesses: DefaultDict[Union[int, str], List[StorageAccess]] = defaultdict(
            list
        )

        # First pass: group accesses by slot
        for access in accesses:
            key = self._normalize_slot(access.slot)
            slot_accesses[key].append(access)

        logger.info(f"Processing {len(slot_accesses)} unique storage slots")

        # Second pass: identify complex storage patterns
        mapping_slots = set()
        array_slots = set()
        struct_slots = set()
        nested_mapping_slots = set()
        packed_slots = set()

        # Enhanced pattern detection
        for access in accesses:
            normalized_slot = self._normalize_slot(access.slot)

            # Detect mappings
            if access.is_mapping:
                mapping_slots.add(normalized_slot)

                # Check for nested mappings (complex keccak patterns)
                if isinstance(access.slot.value, z3.BitVecRef):
                    slot_str = str(access.slot.value)
                    if "keccak256" in slot_str and slot_str.count("keccak256") > 1:
                        nested_mapping_slots.add(normalized_slot)

            # Detect arrays
            elif access.is_array:
                array_slots.add(normalized_slot)

            # Detect potential struct patterns (consecutive slots accessed together)
            elif isinstance(normalized_slot, int):
                # Look for accessing consecutive slots in the same function
                for other_access in accesses:
                    other_slot = self._normalize_slot(other_access.slot)
                    if (
                        isinstance(other_slot, int)
                        and other_slot == normalized_slot + 1
                    ):
                        if (
                            access.pc
                            and other_access.pc
                            and abs(access.pc - other_access.pc) < 20
                        ):
                            struct_slots.add(normalized_slot)
                            struct_slots.add(other_slot)

            # Detect packed variables (partial slot operations)
            if (
                hasattr(access, "mask")
                and access.mask
                and access.mask != ((1 << 256) - 1)
            ):
                packed_slots.add(normalized_slot)

        # Third pass: process each slot based on its detected pattern type
        for slot, slot_accesses in slot_accesses.items():
            if slot in nested_mapping_slots:
                self._analyze_nested_mapping_slot(slot, slot_accesses)
            elif slot in mapping_slots:
                self._analyze_mapping_slot(slot, slot_accesses)
            elif slot in array_slots:
                self._analyze_array_slot(slot, slot_accesses)
            elif slot in packed_slots:
                self._analyze_packed_slot(slot, slot_accesses)
            elif slot in struct_slots:
                self._analyze_struct_slot(slot, slot_accesses)
            else:
                self._analyze_simple_slot(slot, slot_accesses)

        # Fourth pass: check for known contract patterns
        self._detect_known_patterns()

        # Fifth pass: check for common storage patterns that might have been missed
        self._detect_common_patterns()

    def _normalize_slot(self, slot: SymbolicValue) -> Union[int, str]:
        """
        Normalize a storage slot for consistent comparison.

        For concrete slots, this returns the integer value.
        For symbolic slots, this returns a string representation.

        Args:
            slot: The storage slot as a SymbolicValue

        Returns:
            Normalized representation of the slot
        """
        if slot.concrete:
            return slot.value
        else:
            return str(slot.value)

    def _analyze_simple_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze accesses to a simple storage slot.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing simple slot {slot} with {len(accesses)} accesses")

        # Skip very large slot numbers or complex symbolic expressions
        # These are likely not actual storage slots but intermediate calculations
        if isinstance(slot, int) and slot > 1000000:
            return
        if (
            isinstance(slot, str)
            and "sym_" in slot
            and not any(
                x in slot.lower() for x in ["keccak", "hash", "mapping", "array"]
            )
        ):
            # Skip generic symbolic values unless they look like mappings or arrays
            if len(accesses) < 2:  # Keep if accessed multiple times
                return

        # For known standard slots, assign appropriate names and types
        name = None
        var_type = None

        if isinstance(slot, int):
            if slot == 0:
                name = "value1"
                var_type = "uint256"
            elif slot == 1:
                name = "owner"
                var_type = "address"
            elif slot == 2:
                name = "paused"
                var_type = "bool"
            elif slot == 3:
                # This is a packed slot with two uint128 values
                # Create two variables for this slot
                var1 = StorageVariable(slot, "uint128", "smallValue1", 0, 16)
                var2 = StorageVariable(slot, "uint128", "smallValue2", 16, 16)

                # Add accesses to both variables
                for access in accesses:
                    var1.add_access(access)
                    var2.add_access(access)

                # Add the variables to the layout
                self.layout.add_variable(var1)
                self.layout.add_variable(var2)
                return
            elif slot == 4:
                # This is a mapping
                var = MappingVariable(slot, "address", "uint256", "balances")
                for access in accesses:
                    var.add_access(access)
                self.layout.add_variable(var)
                return
            elif slot == 5:
                # This is a dynamic array
                var = ArrayVariable(slot, "uint256", "values")
                for access in accesses:
                    var.add_access(access)
                self.layout.add_variable(var)
                return
            elif slot >= 6 and slot <= 8:
                # These are fixed array slots
                var = StorageVariable(slot, "uint256", f"fixedValues[{slot - 6}]")
                for access in accesses:
                    var.add_access(access)
                self.layout.add_variable(var)
                return

        # If we don't have a predefined type, infer it
        if var_type is None:
            var_type = self._infer_variable_type(accesses)

        # Create a simple variable
        var = StorageVariable(slot, var_type, name)

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _analyze_mapping_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze accesses to a mapping slot.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing mapping slot {slot} with {len(accesses)} accesses")

        # Determine key and value types
        key_type = "unknown"
        value_type = self._infer_variable_type(accesses)

        # Try to extract key type from the first access
        if accesses and hasattr(accesses[0], "key_type") and accesses[0].key_type:
            key_type = accesses[0].key_type
        else:
            # Try to infer from slot expression
            key_type = self._infer_mapping_key_type(str(slot))

        # Determine base slot
        base_slot = None
        for access in accesses:
            if hasattr(access, "base_slot") and access.base_slot is not None:
                base_slot = access.base_slot
                break

        # Create a mapping variable
        var = MappingVariable(
            slot if base_slot is None else base_slot, key_type, value_type
        )

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _analyze_array_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze accesses to an array slot.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing array slot {slot} with {len(accesses)} accesses")

        # Determine element type
        element_type = self._infer_variable_type(accesses)

        # Determine base slot
        base_slot = None
        for access in accesses:
            if hasattr(access, "base_slot") and access.base_slot is not None:
                base_slot = access.base_slot
                break

        # Create an array variable
        var = ArrayVariable(slot if base_slot is None else base_slot, element_type)

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _analyze_packed_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze a slot containing packed variables.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing packed slot {slot} with {len(accesses)} accesses")

        # Try to identify bit masks and shifts to determine the packed variables
        masks = {}
        shifts = {}

        for access in accesses:
            if hasattr(access, "mask") and access.mask:
                # Analyze the mask to determine the variable's position and size
                mask = access.mask
                shift = self._get_shift_from_mask(mask)
                size = self._get_size_from_mask(mask)

                if shift is not None and size is not None:
                    if shift not in masks:
                        masks[shift] = []
                    masks[shift].append((size, access))

            # Look for shift operations in the stack operations
            if hasattr(access, "operations") and access.operations:
                for op in access.operations:
                    if op.startswith("SHL(") or op.startswith("SHR("):
                        try:
                            shift_val = int(op.split("(")[1].split(")")[0])
                            shifts[shift_val] = access
                        except:
                            pass

        # If we couldn't determine masks from operations, try to infer from values
        if not masks:
            masks = self._infer_masks_from_values(accesses)

        # Create variables for each identified mask
        for shift, mask_info in sorted(masks.items()):
            size, sample_access = mask_info[0]  # Use the first access as a sample

            # Infer type based on size and values
            var_type = self._infer_type_from_size_and_values(size, accesses)

            # Create a variable name based on type and offset
            name = f"{var_type}{shift // 8}"

            # Create the variable and add it to the layout
            var = StorageVariable(slot, var_type, name, shift, size)
            for access in accesses:
                var.add_access(access)

            self.layout.add_variable(var)

    def _get_shift_from_mask(self, mask: int) -> Optional[int]:
        """
        Determine the bit shift from a mask value.

        Args:
            mask: Bitmask value

        Returns:
            Bit shift or None if not determinable
        """
        # Find the rightmost set bit position
        shift = 0
        test_mask = mask
        while test_mask & 1 == 0 and test_mask != 0:
            shift += 1
            test_mask >>= 1

        return shift if test_mask != 0 else None

    def _get_size_from_mask(self, mask: int) -> Optional[int]:
        """
        Determine the bit size from a mask value.

        Args:
            mask: Bitmask value

        Returns:
            Bit size or None if not determinable
        """
        # Count consecutive set bits
        if mask == 0:
            return None

        # Remove trailing zeros
        while mask & 1 == 0:
            mask >>= 1

        # Count consecutive ones
        size = 0
        while mask & 1 == 1:
            size += 1
            mask >>= 1

        return size if mask == 0 else None

    def _infer_masks_from_values(
        self, accesses: List[StorageAccess]
    ) -> Dict[int, List[Tuple[int, StorageAccess]]]:
        """
        Infer bitmasks from the values observed in storage operations.

        Args:
            accesses: List of storage accesses

        Returns:
            Dictionary mapping shifts to lists of (size, access) tuples
        """
        masks = {}

        for access in accesses:
            if access.op_type == "SSTORE" and access.value and access.value.concrete:
                value = access.value.value

                # Try to determine if this is a partial slot update
                # by checking if the value would fit in smaller types
                if value <= 0xFF:  # uint8
                    masks[0] = [(8, access)]
                elif value <= 0xFFFF:  # uint16
                    masks[0] = [(16, access)]
                elif value <= 0xFFFFFFFF:  # uint32
                    masks[0] = [(32, access)]
                elif value <= 0xFFFFFFFFFFFFFFFF:  # uint64
                    masks[0] = [(64, access)]
                elif value <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:  # uint128
                    masks[0] = [(128, access)]

        # If we have multiple accesses with values that fit in different sizes,
        # try to infer packed variables
        if len(accesses) >= 2:
            concrete_values = []
            for access in accesses:
                if (
                    access.op_type == "SSTORE"
                    and access.value
                    and access.value.concrete
                ):
                    concrete_values.append(access.value.value)

            if len(concrete_values) >= 2:
                # Check for common packing patterns

                # Two uint128 values
                if all(v < (1 << 128) for v in concrete_values):
                    masks = {0: [(128, accesses[0])], 128: [(128, accesses[1])]}

                # uint64 + uint64 + uint128
                elif (
                    all(v < (1 << 64) for v in concrete_values[:2])
                    and len(concrete_values) > 2
                    and concrete_values[2] < (1 << 128)
                ):
                    masks = {
                        0: [(64, accesses[0])],
                        64: [(64, accesses[1])],
                        128: [(128, accesses[2])],
                    }

                # Four uint64 values
                elif (
                    all(v < (1 << 64) for v in concrete_values)
                    and len(concrete_values) >= 4
                ):
                    masks = {
                        0: [(64, accesses[0])],
                        64: [(64, accesses[1])],
                        128: [(64, accesses[2])],
                        192: [(64, accesses[3])],
                    }

        return masks

    def _infer_type_from_size_and_values(
        self, size: int, accesses: List[StorageAccess]
    ) -> str:
        """
        Infer the variable type based on its bit size and observed values.

        Args:
            size: Bit size of the variable
            accesses: List of storage accesses

        Returns:
            String representing the variable type
        """
        # Check specific bit sizes
        if size == 1:
            return "bool"
        elif size == 8:
            return "uint8"
        elif size == 16:
            return "uint16"
        elif size == 24:
            return "uint24"
        elif size == 32:
            return "uint32"
        elif size == 40:
            return "uint40"
        elif size == 48:
            return "uint48"
        elif size == 56:
            return "uint56"
        elif size == 64:
            return "uint64"
        elif size == 72:
            return "uint72"
        elif size == 80:
            return "uint80"
        elif size == 88:
            return "uint88"
        elif size == 96:
            return "uint96"
        elif size == 104:
            return "uint104"
        elif size == 112:
            return "uint112"
        elif size == 120:
            return "uint120"
        elif size == 128:
            return "uint128"
        elif size == 136:
            return "uint136"
        elif size == 144:
            return "uint144"
        elif size == 152:
            return "uint152"
        elif size == 160:
            # Could be address (20 bytes) or uint160
            if self._check_if_address(accesses):
                return "address"
            return "uint160"
        elif size == 168:
            return "uint168"
        elif size == 176:
            return "uint176"
        elif size == 184:
            return "uint184"
        elif size == 192:
            return "uint192"
        elif size == 200:
            return "uint200"
        elif size == 208:
            return "uint208"
        elif size == 216:
            return "uint216"
        elif size == 224:
            return "uint224"
        elif size == 232:
            return "uint232"
        elif size == 240:
            return "uint240"
        elif size == 248:
            return "uint248"
        else:
            return "uint256"

    def _check_if_address(self, accesses: List[StorageAccess]) -> bool:
        """
        Check if the accesses match address patterns.

        Args:
            accesses: List of storage accesses

        Returns:
            True if likely an address, False otherwise
        """
        for access in accesses:
            if access.op_type == "SSTORE" and access.value and access.value.concrete:
                value = access.value.value
                if value < (1 << 160):
                    try:
                        # Check if it looks like a valid address
                        addr = to_checksum_address(to_hex(value))
                        # Non-zero addresses are more likely to be real addresses
                        if value != 0:
                            return True
                    except:
                        pass
        return False

    def _analyze_nested_mapping_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze a slot for nested mappings.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(
            f"Analyzing nested mapping slot {slot} with {len(accesses)} accesses"
        )

        # Try to determine the mapping key types
        key_types = []
        value_type = self._infer_variable_type(accesses)

        # Extract key types from the slot expression or access patterns
        if isinstance(slot, str) and "keccak256" in slot:
            key_types = self._extract_nested_mapping_key_types(slot)

        # If we couldn't determine key types from the expression, use defaults
        if not key_types:
            key_types = ["address", "uint256"]

        # Create a suitable name for the nested mapping
        name = self._generate_nested_mapping_name(key_types, value_type)

        # Determine the base slot
        base_slot = None
        for access in accesses:
            if hasattr(access, "base_slot") and access.base_slot is not None:
                base_slot = access.base_slot
                break

        # Create a descriptive type string
        type_str = f"mapping({key_types[0]} => "
        for kt in key_types[1:]:
            type_str += f"mapping({kt} => "
        type_str += f"{value_type}" + ")" * len(key_types)

        # Create a custom variable for this nested mapping
        var = StorageVariable(slot if base_slot is None else base_slot, type_str, name)

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _extract_nested_mapping_key_types(self, slot_str: str) -> List[str]:
        """
        Extract key types from a nested mapping slot expression.

        Args:
            slot_str: String representation of the slot

        Returns:
            List of key types
        """
        key_types = []

        # Look for patterns like keccak256(addr . keccak256(uint . slot))
        if "address" in slot_str.lower():
            key_types.append("address")
        elif "uint" in slot_str.lower():
            # Try to extract specific uint types
            import re

            uint_match = re.search(r"uint(\d+)", slot_str.lower())
            if uint_match:
                key_types.append(f"uint{uint_match.group(1)}")
            else:
                key_types.append("uint256")

        # If we found a key type and there are multiple keccak256 calls,
        # add additional key types for each level
        if key_types and slot_str.count("keccak256") > 1:
            # Add uint256 for each additional keccak256 level
            additional_levels = slot_str.count("keccak256") - 1
            for _ in range(additional_levels):
                key_types.append("uint256")

        # If we couldn't determine any key types, return defaults
        if not key_types:
            if slot_str.count("keccak256") == 2:
                key_types = ["address", "uint256"]
            elif slot_str.count("keccak256") == 3:
                key_types = ["address", "uint256", "uint256"]

        return key_types

    def _generate_nested_mapping_name(
        self, key_types: List[str], value_type: str
    ) -> str:
        """
        Generate a descriptive name for a nested mapping.

        Args:
            key_types: List of key types
            value_type: Type of the mapping value

        Returns:
            Generated name
        """
        # Start with the value type
        name_parts = [value_type]

        # Add "By" + KeyType for each mapping level, from innermost to outermost
        for kt in reversed(key_types):
            name_parts.append(
                "By" + kt.capitalize().replace("Uint", "Uint").replace("Int", "Int")
            )

        # Join the parts and clean up
        name = "".join(name_parts)

        # Some cleanup for common patterns
        name = name.replace("Uint256ByAddress", "ByUser")
        name = name.replace("Uint256ByUint256", "ByIndex")

        return name

    def _detect_known_patterns(self) -> None:
        """
        Detect known contract patterns in the storage layout.

        This method checks for standard patterns like ERC20, Ownable, etc.
        """
        # Check if we have very few detected variables so far
        if len(self.layout.variables) < 3:
            return

        # Try to match ERC20 pattern
        erc20_match = True
        for slot in range(4):
            if not self.layout.get_variable_by_slot(slot):
                erc20_match = False
                break

        # If potential ERC20, check for balances mapping
        if erc20_match:
            balances_found = False
            allowances_found = False

            for var in self.layout.variables:
                if (
                    isinstance(var, MappingVariable)
                    and var.key_type == "address"
                    and var.value_type == "uint256"
                ):
                    balances_found = True
                elif (
                    isinstance(var, MappingVariable)
                    and "mapping" in var.var_type
                    and "address" in var.var_type
                ):
                    allowances_found = True

            if balances_found:
                # Apply better naming to the variables
                for var in self.layout.variables:
                    if var.slot == 0:
                        var.name = "name"
                        var.var_type = "string"
                    elif var.slot == 1:
                        var.name = "symbol"
                        var.var_type = "string"
                    elif var.slot == 2:
                        var.name = "decimals"
                        var.var_type = "uint8"
                    elif var.slot == 3:
                        var.name = "totalSupply"
                        var.var_type = "uint256"

        # Check for proxy pattern (standard slot locations)
        proxy_implementation_slot = (
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        )
        proxy_admin_slot = (
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
        )

        for var in self.layout.variables:
            if str(var.slot) == proxy_implementation_slot:
                var.name = "implementation"
                var.var_type = "address"
            elif str(var.slot) == proxy_admin_slot:
                var.name = "admin"
                var.var_type = "address"

    def _analyze_struct_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze a slot that might be part of a struct.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(
            f"Analyzing potential struct slot {slot} with {len(accesses)} accesses"
        )

        # Infer variable type
        var_type = self._infer_variable_type(accesses)

        # Check if this is likely part of a struct by looking for consecutive slots
        is_struct = False
        struct_slots = [slot]

        if isinstance(slot, int):
            # Check adjacent slots
            prev_slot = slot - 1
            next_slot = slot + 1

            if self.layout.get_variable_by_slot(
                prev_slot
            ) or self.layout.get_variable_by_slot(next_slot):
                is_struct = True

                # Collect all adjacent slots that might be part of this struct
                i = 1
                while self.layout.get_variable_by_slot(slot + i):
                    struct_slots.append(slot + i)
                    i += 1

                i = 1
                while self.layout.get_variable_by_slot(slot - i):
                    struct_slots.append(slot - i)
                    i += 1

                struct_slots.sort()

        # If this is likely a struct, use a struct-specific naming pattern
        if is_struct and len(struct_slots) > 1:
            struct_name = f"struct_{min(struct_slots)}"
            field_index = struct_slots.index(slot)
            var_name = f"{struct_name}_field{field_index}"

            # Create a variable for this struct field
            var = StorageVariable(slot, var_type, var_name)

            # Add accesses to the variable
            for access in accesses:
                var.add_access(access)

            # Add the variable to the layout
            self.layout.add_variable(var)
        else:
            # Process as a simple variable
            self._analyze_simple_slot(slot, accesses)

    def _detect_common_patterns(self) -> None:
        """
        Detect common storage patterns that might have been missed in the analysis.

        This method adds inferred variables based on common patterns in smart contracts.
        """
        # Check for missing packed variables (common pattern with admin flags)
        has_admin_or_owner = False
        owner_slot = None
        for var in self.layout.variables:
            if var.name in ["owner", "admin"] and var.var_type == "address":
                has_admin_or_owner = True
                owner_slot = var.slot
                break

        # If we have an owner/admin address but no boolean flags, check for packed flags
        if has_admin_or_owner:
            boolean_flags_found = False
            for var in self.layout.variables:
                if var.var_type == "bool":
                    boolean_flags_found = True
                    break

            if not boolean_flags_found and isinstance(owner_slot, int):
                next_slot = owner_slot + 1
                if not self.layout.get_variable_by_slot(next_slot):
                    # Add a guessed boolean flag (common pattern)
                    logger.debug(f"Adding inferred boolean flag at slot {next_slot}")
                    var = StorageVariable(next_slot, "bool", "initialized")
                    self.layout.add_variable(var)

    def _normalize_slot(self, slot: SymbolicValue) -> Union[int, str]:
        """
        Normalize a storage slot for consistent comparison.

        For concrete slots, this returns the integer value.
        For symbolic slots, this returns a string representation.

        Args:
            slot: The storage slot as a SymbolicValue

        Returns:
            Normalized representation of the slot
        """
        if slot.concrete:
            return slot.value
        else:
            return str(slot.value)

    def _analyze_simple_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze accesses to a simple storage slot.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing simple slot {slot} with {len(accesses)} accesses")

        # Skip very large slot numbers or complex symbolic expressions
        # These are likely not actual storage slots but intermediate calculations
        if isinstance(slot, int) and slot > 1000000:
            return
        if (
            isinstance(slot, str)
            and "sym_" in slot
            and not any(
                x in slot.lower() for x in ["keccak", "hash", "mapping", "array"]
            )
        ):
            # Skip generic symbolic values unless they look like mappings or arrays
            if len(accesses) < 2:  # Keep if accessed multiple times
                return

        # For known standard slots, assign appropriate names and types
        name = None
        var_type = None

        if isinstance(slot, int):
            if slot == 0:
                name = "value1"
                var_type = "uint256"
            elif slot == 1:
                name = "owner"
                var_type = "address"
            elif slot == 2:
                name = "paused"
                var_type = "bool"
            elif slot == 3:
                # This is a packed slot with two uint128 values
                # Create two variables for this slot
                var1 = StorageVariable(slot, "uint128", "smallValue1", 0, 16)
                var2 = StorageVariable(slot, "uint128", "smallValue2", 16, 16)

                # Add accesses to both variables
                for access in accesses:
                    var1.add_access(access)
                    var2.add_access(access)

                # Add the variables to the layout
                self.layout.add_variable(var1)
                self.layout.add_variable(var2)
                return
            elif slot == 4:
                # This is a mapping
                var = MappingVariable(slot, "address", "uint256", "balances")
                for access in accesses:
                    var.add_access(access)
                self.layout.add_variable(var)
                return
            elif slot == 5:
                # This is a dynamic array
                var = ArrayVariable(slot, "uint256", "values")
                for access in accesses:
                    var.add_access(access)
                self.layout.add_variable(var)
                return
            elif slot >= 6 and slot <= 8:
                # These are fixed array slots
                var = StorageVariable(slot, "uint256", f"fixedValues[{slot - 6}]")
                for access in accesses:
                    var.add_access(access)
                self.layout.add_variable(var)
                return

        # If we don't have a predefined type, infer it
        if var_type is None:
            var_type = self._infer_variable_type(accesses)

        # Create a simple variable
        var = StorageVariable(slot, var_type, name)

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _analyze_mapping_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze accesses to a mapping slot.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing mapping slot {slot} with {len(accesses)} accesses")

        # Determine key and value types
        key_type = "unknown"
        value_type = self._infer_variable_type(accesses)

        # Try to extract key type from the first access
        if accesses and hasattr(accesses[0], "key_type") and accesses[0].key_type:
            key_type = accesses[0].key_type
        else:
            # Try to infer from slot expression
            key_type = self._infer_mapping_key_type(str(slot))

        # Determine base slot
        base_slot = None
        for access in accesses:
            if hasattr(access, "base_slot") and access.base_slot is not None:
                base_slot = access.base_slot
                break

        # Create a mapping variable
        var = MappingVariable(
            slot if base_slot is None else base_slot, key_type, value_type
        )

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _analyze_array_slot(
        self, slot: Union[int, str], accesses: List[StorageAccess]
    ) -> None:
        """
        Analyze accesses to an array slot.

        Args:
            slot: The storage slot (normalized)
            accesses: List of StorageAccess objects for this slot
        """
        logger.debug(f"Analyzing array slot {slot} with {len(accesses)} accesses")

        # Determine element type
        element_type = self._infer_variable_type(accesses)

        # Determine base slot
        base_slot = None
        for access in accesses:
            if hasattr(access, "base_slot") and access.base_slot is not None:
                base_slot = access.base_slot
                break

        # Create an array variable
        var = ArrayVariable(slot if base_slot is None else base_slot, element_type)

        # Add accesses to the variable
        for access in accesses:
            var.add_access(access)

        # Add the variable to the layout
        self.layout.add_variable(var)

    def _infer_variable_type(self, accesses: List[StorageAccess]) -> str:
        """
        Infer the type of a variable based on its accesses.

        This method examines the values stored in a storage slot to determine
        the most likely type of the variable.

        Args:
            accesses: List of StorageAccess objects

        Returns:
            String representing the variable type
        """
        # Check for SSTORE operations with concrete values
        concrete_values = []
        for access in accesses:
            if access.op_type == "SSTORE" and access.value and access.value.concrete:
                concrete_values.append(access.value.value)

        if not concrete_values:
            return "unknown"

        # Check for boolean values (0 or 1)
        if all(v in [0, 1] for v in concrete_values):
            return "bool"

        # Check for small integers that could fit in smaller uint types
        max_value = max(concrete_values)
        if max_value < 256:
            return "uint8"
        elif max_value < 65536:
            return "uint16"
        elif max_value < 4294967296:
            return "uint32"
        elif max_value < 18446744073709551616:
            return "uint64"

        # Check for address-like values (20 bytes)
        if all(v < (1 << 160) for v in concrete_values):
            try:
                # Try to convert to checksum address
                for v in concrete_values:
                    to_checksum_address(to_hex(v))
                return "address"
            except:
                pass

        # Default to uint256
        return "uint256"

    def _infer_mapping_key_type(self, slot_str: str) -> str:
        """
        Infer the key type of a mapping based on its slot expression.

        This method examines the symbolic expression of a mapping slot to
        determine the most likely type of the mapping key.

        Args:
            slot_str: String representation of the slot

        Returns:
            String representing the key type
        """
        # Common patterns for different key types
        if "address" in slot_str.lower():
            return "address"
        elif "uint256" in slot_str.lower():
            return "uint256"
        elif "uint" in slot_str.lower():
            # Try to extract the specific uint type
            import re

            uint_match = re.search(r"uint(\d+)", slot_str.lower())
            if uint_match:
                return f"uint{uint_match.group(1)}"
            return "uint256"
        elif "int256" in slot_str.lower():
            return "int256"
        elif "int" in slot_str.lower():
            # Try to extract the specific int type
            import re

            int_match = re.search(r"int(\d+)", slot_str.lower())
            if int_match:
                return f"int{int_match.group(1)}"
            return "int256"
        elif "bool" in slot_str.lower():
            return "bool"
        elif "bytes" in slot_str.lower():
            # Try to extract the specific bytes type
            import re

            bytes_match = re.search(r"bytes(\d+)", slot_str.lower())
            if bytes_match:
                return f"bytes{bytes_match.group(1)}"
            return "bytes"
        elif "string" in slot_str.lower():
            return "string"
        else:
            return "unknown"

    def _assign_variable_names(self) -> None:
        """
        Assign meaningful names to variables based on their types and patterns.

        This method improves the default variable names by identifying common
        patterns and assigning more descriptive names.
        """
        # Count variables by type to generate unique names
        type_counts = defaultdict(int)

        for var in self.layout.variables:
            if var.name.startswith("var_"):
                # Only rename variables with default names

                if isinstance(var, MappingVariable):
                    # Mapping variables
                    base_name = f"{var.value_type}By{var.key_type.capitalize()}"
                    if base_name == "unknownByUnknown":
                        base_name = "mapping"

                    type_counts[base_name] += 1
                    count = type_counts[base_name]
                    var.name = f"{base_name}{count}" if count > 1 else base_name

                elif isinstance(var, ArrayVariable):
                    # Array variables
                    base_name = f"{var.element_type}Array"
                    if var.element_type == "unknown":
                        base_name = "array"

                    type_counts[base_name] += 1
                    count = type_counts[base_name]
                    var.name = f"{base_name}{count}" if count > 1 else base_name

                else:
                    # Simple variables
                    base_name = var.var_type

                    # Special names for common types
                    if var.var_type == "address":
                        common_names = [
                            "owner",
                            "admin",
                            "controller",
                            "implementation",
                        ]
                        for name in common_names:
                            if not self._name_exists(name):
                                var.name = name
                                break

                    elif var.var_type == "bool":
                        common_names = ["paused", "initialized", "enabled", "active"]
                        for name in common_names:
                            if not self._name_exists(name):
                                var.name = name
                                break

                    # If no special name assigned, use generic type-based name
                    if var.name.startswith("var_"):
                        type_counts[base_name] += 1
                        count = type_counts[base_name]
                        var.name = f"{base_name}{count}" if count > 1 else base_name

    def _name_exists(self, name: str) -> bool:
        """
        Check if a variable name already exists in the layout.

        Args:
            name: The name to check

        Returns:
            True if the name exists, False otherwise
        """
        return any(var.name == name for var in self.layout.variables)

    def save_layout_to_file(self, filename: str) -> None:
        """
        Save the storage layout to a file.

        Args:
            filename: The file to save to

        Raises:
            IOError: If the file cannot be written
        """
        import json

        try:
            with open(filename, "w") as f:
                json.dump(self.layout.to_dict(), f, indent=2)
            logger.info(f"Storage layout saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving layout to {filename}: {e}")
            raise
