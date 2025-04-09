# rpc/server.py
import json
from typing import Dict, Any, List, Optional
import structlog
from jsonrpcserver import method, serve, Success, Error, Result, dispatch

# Use relative imports for components within the package
from ..swap_detection.analyzer import SwapAnalyzer
from ..core.concolic import ConcolicExecutor  # Import if needed for direct access

logger = structlog.get_logger()

# Global analyzer instance (consider dependency injection for better testing/flexibility)
analyzer: Optional[SwapAnalyzer] = None


def init_analyzer(
    web3_provider: str, network: str = "mainnet", contract_db_path: Optional[str] = None
):
    """Initializes the global SwapAnalyzer instance."""
    global analyzer
    if analyzer is None:
        logger.info(
            "Initializing SwapAnalyzer for RPC server",
            provider=web3_provider,
            network=network,
        )
        try:
            analyzer = SwapAnalyzer(web3_provider, network, contract_db_path)
        except Exception as e:
            logger.exception("Failed to initialize SwapAnalyzer", error=str(e))
            # Decide how to handle initialization failure - maybe prevent server start?
            raise RuntimeError(f"Failed to initialize SwapAnalyzer: {e}") from e
    else:
        logger.warning("SwapAnalyzer already initialized.")


# Define RPC methods using a Methods object for clarity
rpc_methods = Methods()


@rpc_methods.add  # Decorator to register the method
async def detect_eth_usdc_swap(
    tx_hash: str, timeout_seconds: int = 30, use_concolic: bool = True
) -> Result:
    """
    Custom RPC method to detect ETH/USDC swaps in a transaction.
    """
    logger.info("RPC call received: detect_eth_usdc_swap", tx_hash=tx_hash)
    if not analyzer:
        logger.error("RPC Error: Analyzer not initialized")
        return Error(code=-32001, message="Swap analyzer service not initialized")

    try:
        # Note: SwapAnalyzer methods are currently synchronous.
        # If they become async, use 'await' here.
        result_data = analyzer.detect_eth_usdc_swap(
            tx_hash, timeout_seconds, use_concolic
        )
        logger.debug(
            "RPC call successful: detect_eth_usdc_swap",
            tx_hash=tx_hash,
            result=result_data,
        )
        return Success(result_data)
    except Exception as e:
        logger.exception(
            "Error processing detect_eth_usdc_swap RPC call",
            tx_hash=tx_hash,
            error=str(e),
        )
        # Return a generic server error
        return Error(code=-32000, message=f"Error detecting swap: {str(e)}")


@rpc_methods.add
async def analyze_transaction_concolic(
    tx_hash: str, options: Optional[Dict[str, Any]] = None
) -> Result:
    """
    Advanced RPC method exposing more detailed concolic analysis options.
    (Note: Currently, the main analyzer method handles concolic execution.
     This method provides a potential alternative entry point if needed.)
    """
    logger.info(
        "RPC call received: analyze_transaction_concolic",
        tx_hash=tx_hash,
        options=options,
    )
    if not analyzer:
        logger.error("RPC Error: Analyzer not initialized")
        return Error(code=-32001, message="Swap analyzer service not initialized")
    if not hasattr(analyzer, "concolic_executor"):
        logger.error("RPC Error: Concolic executor not available on analyzer")
        return Error(code=-32002, message="Concolic executor component not available")

    options = options or {}
    timeout = options.get("timeout_seconds", 30)
    max_poi = options.get("max_points_of_interest", 10)  # Example option
    max_paths = options.get("max_paths", 5)  # Example option
    max_depth = options.get("max_depth", 100)  # Example option

    try:
        # Directly call the concolic executor's analyze method if needed,
        # or enhance the main SwapAnalyzer method to accept these options.
        # Using the existing method for now:
        result_data = analyzer.concolic_executor.analyze_transaction(
            tx_hash,
            max_poi=max_poi,
            timeout_seconds=timeout,
            max_sym_paths=max_paths,
            max_sym_depth=max_depth,
        )
        logger.debug(
            "RPC call successful: analyze_transaction_concolic",
            tx_hash=tx_hash,
            result=result_data,
        )
        return Success(result_data)
    except Exception as e:
        logger.exception(
            "Error processing analyze_transaction_concolic RPC call",
            tx_hash=tx_hash,
            error=str(e),
        )
        return Error(code=-32000, message=f"Error in concolic analysis: {str(e)}")


# --- Server Startup ---


def start_rpc_server(
    host="0.0.0.0",
    port=8545,
    web3_provider="http://localhost:8545",
    network="mainnet",
    db_path=None,
):
    """Initializes the analyzer and starts the JSON-RPC server."""
    try:
        init_analyzer(web3_provider, network, db_path)
        logger.info(f"Starting JSON-RPC server", host=host, port=port, network=network)
        # Serve using the registered methods
        serve(methods=rpc_methods, host=host, port=port)
        # Note: `serve` blocks execution here.
    except RuntimeError as init_error:
        logger.critical(
            "Failed to start RPC server due to initialization error.", error=init_error
        )
        # Exit or handle appropriately
        return
    except Exception as e:
        logger.critical("Failed to start RPC server.", error=str(e))
        # Exit or handle appropriately
        return


# Example entry point if running this file directly
# Use the deployment script (deployment/deploy.py) for actual runs.
if __name__ == "__main__":
    # Basic configuration for direct run - use deploy.py for proper config
    configure_logging()  # Assumes configure_logging is defined elsewhere or imported
    start_rpc_server()


# Helper to configure logging if running directly (copy from deploy.py if needed)
def configure_logging(log_level="INFO"):
    import logging
    from structlog.stdlib import LoggerFactory

    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level),
        force=True,
    )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            # Use ConsoleRenderer for direct runs for readability
            structlog.dev.ConsoleRenderer(),  # Or JSONRenderer() for structured logs
        ],
        context_class=dict,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logger.info("Logging configured for direct run.")
