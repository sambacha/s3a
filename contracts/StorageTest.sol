// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract StorageTest {
    // Simple storage variables with explicit storage slots
    uint256 public value1;                // slot 0
    address public owner;                 // slot 1
    bool public paused;                   // slot 2
    uint128 public smallValue1;           // slot 3 (first half)
    uint128 public smallValue2;           // slot 3 (second half)
    
    // Mapping in slot 4
    mapping(address => uint256) public balances;
    
    // Dynamic array starting at slot 5
    uint256[] public values;
    
    // Fixed array uses 3 slots starting at slot 6
    uint256[3] public fixedValues;
    
    // Events for tracking operations
    event ValueSet(uint256 value);
    event Transfer(address from, address to, uint256 amount);
    
    constructor() {
        owner = msg.sender;
        value1 = 100;
        
        // Initialize the fixed array
        fixedValues[0] = 10;
        fixedValues[1] = 20;
        fixedValues[2] = 30;
        
        // Add some values to the dynamic array
        values.push(1000);
        values.push(2000);
        
        // Set some packed values
        smallValue1 = 123;
        smallValue2 = 456;
    }
    
    // Simple setter function with direct storage access
    function setValue(uint256 newValue) public {
        require(!paused, "Contract is paused");
        
        // Direct SSTORE operation
        value1 = newValue;
        
        emit ValueSet(newValue);
    }
    
    // Function that accesses and modifies mapping storage
    function deposit() public payable {
        require(!paused, "Contract is paused");
        
        // Update balance (SLOAD + SSTORE)
        balances[msg.sender] += msg.value;
    }
    
    // Function with multiple storage operations
    function transfer(address to, uint256 amount) public {
        require(!paused, "Contract is paused");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Storage operations on mappings
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
    }
    
    // Function that interacts with the dynamic array
    function addValue(uint256 newValue) public {
        require(!paused, "Contract is paused");
        
        // Modifies array length and adds element
        values.push(newValue);
    }
    
    // Function to read and update fixed array
    function updateFixedValue(uint256 index, uint256 newValue) public {
        require(index < 3, "Index out of bounds");
        require(!paused, "Contract is paused");
        
        // Storage access to fixed array
        fixedValues[index] = newValue;
    }
    
    // Function with multiple storage reads but no writes
    function getTotalBalance(address user1, address user2) public view returns (uint256) {
        return balances[user1] + balances[user2];
    }
    
    // Admin function to toggle pause state
    function togglePause() public {
        require(msg.sender == owner, "Only owner can pause");
        
        // Toggle the paused flag in storage
        paused = !paused;
    }
    
    // Function that modifies packed storage variables
    function setSmallValues(uint128 val1, uint128 val2) public {
        require(!paused, "Contract is paused");
        
        // These variables are packed in the same slot
        smallValue1 = val1;
        smallValue2 = val2;
    }
}