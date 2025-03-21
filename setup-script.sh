#!/bin/bash

# Exit on error
set -e

echo "Setting up Storage Layout Tracer environment..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Please install Python 3."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "pip not found. Please install pip."
    exit 1
fi

# Check if solc is installed
if ! command -v solc &> /dev/null; then
    echo "Solidity compiler (solc) not found. Installing..."
    # Different install methods depending on OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        sudo add-apt-repository ppa:ethereum/ethereum
        sudo apt-get update
        sudo apt-get install solc
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        brew update
        brew install solidity
    else
        echo "Please install solc manually: https://docs.soliditylang.org/en/latest/installing-solidity.html"
        exit 1
    fi
fi

# Check if Foundry is installed
if ! command -v anvil &> /dev/null; then
    echo "Foundry not found. Installing..."
    curl -L https://foundry.paradigm.xyz | bash
    source ~/.bashrc
    foundryup
fi

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Setup complete! You can now run the analyzer with:"
echo "source venv/bin/activate"
echo "python run.py --anvil"
