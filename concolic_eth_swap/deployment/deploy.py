
import argparse
import os
import logging
import structlog
from structlog import configure
from structlog.stdlib import LoggerFactory
import multiprocessing
import sys
from typing import List # Import List

configure(logger_factory=LoggerFactory())

# Ensure the package root is in the Python path if running as a script
# This might be needed if running `python deployment/deploy.py` directly
# from the project root. A better approach is usually installing the package
# or using `python -m concolic_eth_swap.deployment.deploy`.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now relative imports should work
from concolic_eth_swap.rpc.server import start_rpc_server

def configure_logging(log_level="INFO"):
    """Configure structured logging"""
    # Check if already configured
    if structlog.is_configured():
        return

    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level.upper(), logging.INFO),
        stream=sys.stdout, # Use stdout for better compatibility with process managers
        force=True, # Override any root logger config
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
            # Use JSONRenderer for production environments
            structlog.processors.JSONRenderer()
            # Or use ConsoleRenderer for development:
            # structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logger = structlog.get_logger()
    logger.info("Logging configured", log_level=log_level)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Run Concolic ETH/USDC Swap Detection Service')
    parser.add_argument('--host', default=os.environ.get('HOST', '0.0.0.0'), help='Host to bind the RPC server to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 8545)), help='Port to bind the RPC server to (default: 8545)')
    parser.add_argument('--web3-provider', default=os.environ.get('WEB3_PROVIDER_URL', 'http://localhost:8545'), help='Web3 provider URL (default: http://localhost:8545)')
    parser.add_argument('--network', default=os.environ.get('NETWORK', 'mainnet'), choices=['mainnet', 'goerli', 'sepolia'], help='Ethereum network (default: mainnet)')
    parser.add_argument('--db-path', default=os.environ.get('CONTRACT_DB_PATH'), help='Path to contract database JSON file (optional)')
    parser.add_argument('--workers', type=int, default=int(os.environ.get('WORKERS', 1)), help='Number of worker processes (for distributed mode, default: 1)')
    parser.add_argument('--distributed', action='store_true', default=os.environ.get('DISTRIBUTED_MODE', 'false').lower() == 'true', help='Enable distributed execution mode (requires Redis)')
    parser.add_argument('--log-level', default=os.environ.get('LOG_LEVEL', 'INFO'), choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Logging level (default: INFO)')
    return parser.parse_args()

def run_worker(worker_id: int, args: argparse.Namespace):
    """Run a worker process for distributed execution"""
    # Configure logging for each worker process
    configure_logging(args.log_level)
    # Create a logger specific to this worker
    logger = structlog.get_logger(f"worker-{worker_id}")
    logger.info("Starting worker process", worker_id=worker_id, pid=os.getpid())

    # Offset port for each worker if running multiple RPC servers directly
    # (Alternative: Use a single load balancer in front)
    port = args.port + worker_id

    try:
        # Each worker runs its own RPC server instance
        start_rpc_server(
            host=args.host,
            port=port,
            web3_provider=args.web3_provider,
            network=args.network,
            db_path=args.db_path
        )
        logger.info(f"Worker {worker_id} finished.")
    except Exception as e:
        logger.exception(f"Worker {worker_id} encountered an error", error=str(e))
        # Exit with error status?
        sys.exit(1)


def main():
    """Main entry point for deployment"""
    args = parse_args()
    configure_logging(args.log_level)
    logger = structlog.get_logger("deploy_main")

    if args.distributed and args.workers > 1:
        logger.info("Starting in distributed mode", workers=args.workers)
        processes: List[multiprocessing.Process] = []
        for i in range(args.workers):
            # Pass args object to the worker function
            p = multiprocessing.Process(target=run_worker, args=(i, args), name=f"Worker-{i}")
            p.start()
            processes.append(p)
            logger.info(f"Started worker process {i}", pid=p.pid)

        # Wait for all worker processes to complete
        try:
            for p in processes:
                p.join()
            logger.info("All worker processes finished.")
        except KeyboardInterrupt:
            logger.warning("Received KeyboardInterrupt, terminating worker processes...")
            for p in processes:
                if p.is_alive():
                    p.terminate() # Send SIGTERM
                    p.join(timeout=5) # Wait briefly
                if p.is_alive():
                    p.kill() # Force kill if still running
            logger.info("Worker processes terminated.")
    else:
        logger.info("Starting in single process mode")
        # Run the server directly in the main process
        start_rpc_server(
            host=args.host,
            port=args.port,
            web3_provider=args.web3_provider,
            network=args.network,
            db_path=args.db_path
        )

if __name__ == "__main__":
    main()
