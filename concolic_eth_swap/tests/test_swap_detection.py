# tests/test_swap_detection.py
import pytest
from unittest.mock import MagicMock, patch
import json
import os

# Adjust imports based on actual project structure
from ..swap_detection.analyzer import SwapAnalyzer
from ..swap_detection.patterns import (
    SwapMethodSignature,
)  # Import if needed for mocking

# --- Test Fixtures ---

# Define fixture directory relative to this test file
FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

# Reuse fixtures from test_concolic if they are defined there and needed here
# Or define specific fixtures for SwapAnalyzer tests


@pytest.fixture(scope="module")
def swap_tx_receipt():
    """Load a receipt for a swap transaction"""
    fixture_path = os.path.join(FIXTURE_DIR, "swap_tx_receipt.json")
    if not os.path.exists(fixture_path):
        pytest.skip(f"Fixture file not found: {fixture_path}")
    with open(fixture_path, "r") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def non_swap_tx_receipt():
    """Load a receipt for a non-swap transaction"""
    fixture_path = os.path.join(FIXTURE_DIR, "non_swap_tx_receipt.json")
    if not os.path.exists(fixture_path):
        pytest.skip(f"Fixture file not found: {fixture_path}")
    with open(fixture_path, "r") as f:
        return json.load(f)


@pytest.fixture
def mock_web3_for_analyzer(
    eth_usdc_swap_tx, swap_tx_receipt, non_swap_tx, non_swap_tx_receipt
):
    """Mock Web3 instance specifically for SwapAnalyzer tests"""
    mock = MagicMock()
    mock.is_connected.return_value = True

    def mock_get_tx(tx_hash):
        if tx_hash == "0xSWAP_HASH":
            return eth_usdc_swap_tx
        if tx_hash == "0xNON_SWAP_HASH":
            return non_swap_tx
        return None  # Simulate transaction not found

    def mock_get_receipt(tx_hash):
        if tx_hash == "0xSWAP_HASH":
            return swap_tx_receipt
        if tx_hash == "0xNON_SWAP_HASH":
            return non_swap_tx_receipt
        return None

    mock.eth.get_transaction.side_effect = mock_get_tx
    mock.eth.get_transaction_receipt.side_effect = mock_get_receipt
    return mock


# --- Test Cases ---


@patch("concolic_eth_swap.swap_detection.analyzer.ConcolicExecutor")
@patch("concolic_eth_swap.swap_detection.analyzer.Web3")
def test_swap_analyzer_init(MockWeb3, MockConcolicExecutor):
    """Test SwapAnalyzer initialization"""
    mock_web3_instance = MockWeb3.return_value
    mock_web3_instance.is_connected.return_value = True
    mock_concolic_instance = MockConcolicExecutor.return_value

    analyzer = SwapAnalyzer("http://mock-provider:8545", network="mainnet")

    assert analyzer.web3 is not None
    assert analyzer.concolic_executor is not None
    assert analyzer.network == "mainnet"
    MockWeb3.assert_called_with(MockWeb3.HTTPProvider("http://mock-provider:8545"))
    MockConcolicExecutor.assert_called_with("http://mock-provider:8545", "mainnet")


@patch("concolic_eth_swap.swap_detection.analyzer.ConcolicExecutor")
@patch("concolic_eth_swap.swap_detection.analyzer.Web3")
def test_detect_swap_quick_signature(
    MockWeb3, MockConcolicExecutor, mock_web3_for_analyzer, eth_usdc_swap_tx
):
    """Test detection via quick signature check"""
    MockWeb3.return_value = mock_web3_for_analyzer  # Use the configured mock

    # Mock the concolic executor so it's not called
    mock_concolic = MockConcolicExecutor.return_value

    analyzer = SwapAnalyzer("http://mock-provider:8545")
    # Manually patch _extract_swap_path to simulate successful path extraction for ETH/USDC
    analyzer._extract_swap_path = MagicMock(
        return_value=[
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        ]
    )

    result = analyzer.detect_eth_usdc_swap(
        "0xSWAP_HASH", use_concolic=False
    )  # Disable concolic

    assert result["is_swap"] is True
    assert result["detection_method"].startswith("Direct call:")
    assert result["swap_details"]["path"] is not None
    mock_concolic.analyze_transaction.assert_not_called()  # Ensure concolic wasn't called


@patch("concolic_eth_swap.swap_detection.analyzer.ConcolicExecutor")
@patch("concolic_eth_swap.swap_detection.analyzer.Web3")
def test_detect_swap_quick_logs(
    MockWeb3, MockConcolicExecutor, mock_web3_for_analyzer, swap_tx_receipt
):
    """Test detection via event logs"""
    # Modify the swap TX mock so signature check fails, forcing log check
    mock_swap_tx_no_sig = mock_web3_for_analyzer.eth.get_transaction(
        "0xSWAP_HASH"
    ).copy()
    mock_swap_tx_no_sig["input"] = "0xDEADBEEF"  # Invalid method ID
    mock_web3_for_analyzer.eth.get_transaction.side_effect = (
        lambda h: mock_swap_tx_no_sig if h == "0xSWAP_HASH" else None
    )

    MockWeb3.return_value = mock_web3_for_analyzer
    mock_concolic = MockConcolicExecutor.return_value

    analyzer = SwapAnalyzer("http://mock-provider:8545")
    # Assume the swap_tx_receipt fixture contains a valid Swap event from a known pool
    # Need to ensure is_known_eth_usdc_pool returns True for the log address in the fixture
    with patch(
        "concolic_eth_swap.swap_detection.analyzer.is_known_eth_usdc_pool",
        return_value=True,
    ):
        result = analyzer.detect_eth_usdc_swap("0xSWAP_HASH", use_concolic=False)

    assert result["is_swap"] is True
    assert result["detection_method"].startswith("Swap Event from known ETH/USDC Pool")
    assert "pool_address" in result["swap_details"]
    mock_concolic.analyze_transaction.assert_not_called()


@patch("concolic_eth_swap.swap_detection.analyzer.ConcolicExecutor")
@patch("concolic_eth_swap.swap_detection.analyzer.Web3")
def test_detect_swap_concolic(
    MockWeb3,
    MockConcolicExecutor,
    mock_web3_for_analyzer,
    non_swap_tx,
    non_swap_tx_receipt,
):  # Added non_swap_tx fixture
    """Test detection falls back to concolic analysis"""
    # Use non_swap mocks for tx/receipt so quick checks fail
    mock_web3_for_analyzer.eth.get_transaction.side_effect = (
        lambda h: non_swap_tx if h == "0xCONCOLIC_TEST" else None
    )
    mock_web3_for_analyzer.eth.get_transaction_receipt.side_effect = (
        lambda h: non_swap_tx_receipt if h == "0xCONCOLIC_TEST" else None
    )

    MockWeb3.return_value = mock_web3_for_analyzer
    mock_concolic = MockConcolicExecutor.return_value
    # Configure mock concolic executor to return a positive swap result
    mock_concolic.analyze_transaction.return_value = {
        "tx_hash": "0xCONCOLIC_TEST",
        "analysis_complete": True,
        "execution_time": 15.123,
        "is_swap": True,
        "swap_details": {
            "swap_type": "USDC_TO_ETH",
            "details": {"usdc_spent": "5000000", "eth_received": "2000000000000000"},
        },
    }

    analyzer = SwapAnalyzer("http://mock-provider:8545")
    result = analyzer.detect_eth_usdc_swap("0xCONCOLIC_TEST", use_concolic=True)

    assert result["is_swap"] is True
    assert result["detection_method"] == "Concolic analysis result"
    assert result["swap_details"]["swap_type"] == "USDC_TO_ETH"
    mock_concolic.analyze_transaction.assert_called_once()


@patch("concolic_eth_swap.swap_detection.analyzer.ConcolicExecutor")
@patch("concolic_eth_swap.swap_detection.analyzer.Web3")
def test_detect_no_swap(
    MockWeb3,
    MockConcolicExecutor,
    mock_web3_for_analyzer,
    non_swap_tx,
    non_swap_tx_receipt,
):
    """Test non-swap transaction is correctly identified"""
    mock_web3_for_analyzer.eth.get_transaction.side_effect = (
        lambda h: non_swap_tx if h == "0xNON_SWAP_HASH" else None
    )
    mock_web3_for_analyzer.eth.get_transaction_receipt.side_effect = (
        lambda h: non_swap_tx_receipt if h == "0xNON_SWAP_HASH" else None
    )

    MockWeb3.return_value = mock_web3_for_analyzer
    mock_concolic = MockConcolicExecutor.return_value
    # Configure mock concolic executor to return negative result
    mock_concolic.analyze_transaction.return_value = {
        "tx_hash": "0xNON_SWAP_HASH",
        "analysis_complete": True,
        "is_swap": False,
        "swap_details": {},
    }

    analyzer = SwapAnalyzer("http://mock-provider:8545")
    result = analyzer.detect_eth_usdc_swap("0xNON_SWAP_HASH", use_concolic=True)

    assert result["is_swap"] is False
    assert "error" not in result
    # Ensure concolic was called (as quick checks failed)
    mock_concolic.analyze_transaction.assert_called_once()


# TODO: Add tests for:
# - Invalid tx hash format
# - Transaction not found
# - Transaction reverted
# - Concolic analysis disabled case
# - Timeout during concolic analysis
# - Errors during web3 calls
