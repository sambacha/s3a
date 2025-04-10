# ethereum/trace_collector.py
from typing import Dict, Any, Optional
import structlog
from web3 import Web3

logger = structlog.get_logger()


class TraceCollector:
    def __init__(self, web3_provider_url: str):
        self.web3 = Web3(Web3.HTTPProvider(web3_provider_url))
        if not self.web3.is_connected():
            raise ConnectionError(
                f"Failed to connect to Web3 provider at {web3_provider_url}"
            )

    def get_trace(
        self,
        tx_hash: str,
        tracer_type: str = "callTracer",
        tracer_config: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Collects an execution trace for a given transaction using debug_traceTransaction.

        Args:
            tx_hash: The hash of the transaction to trace.
            tracer_type: The type of tracer to use (e.g., 'callTracer', 'prestateTracer', custom JS tracer).
            tracer_config: Optional configuration specific to the tracer.

        Returns:
            The trace result from the RPC node.
        """
        logger.info("Collecting trace", tx_hash=tx_hash, tracer=tracer_type)
        config = tracer_config or {}  # Default to empty config if None

        try:
            trace = self.web3.provider.make_request(
                "debug_traceTransaction",
                [tx_hash, {"tracer": tracer_type, "tracerConfig": config}],
            )

            if "error" in trace:
                logger.error(
                    "Error received from debug_traceTransaction",
                    tx_hash=tx_hash,
                    error=trace["error"],
                    tracer=tracer_type,
                )
                raise Exception(
                    f"Trace error for {tx_hash} using {tracer_type}: {trace['error']}"
                )

            if "result" not in trace:
                logger.error(
                    "Unexpected trace format: 'result' key missing",
                    tx_hash=tx_hash,
                    trace_response=trace,
                )
                raise ValueError(f"Unexpected trace format received for {tx_hash}")

            logger.debug(
                "Successfully collected trace", tx_hash=tx_hash, tracer=tracer_type
            )
            return trace["result"]

        except Exception as e:
            logger.exception(
                "Error during trace collection",
                tx_hash=tx_hash,
                tracer=tracer_type,
                error=str(e),
            )
            raise  # Re-raise the exception


# Example usage (optional)
if __name__ == "__main__":
    provider = "http://localhost:8545"  # Replace with your provider
    collector = TraceCollector(provider)
    # Replace with a real transaction hash
    test_tx_hash = "0x..."
    try:
        # Example: Get a basic call trace
        call_trace = collector.get_trace(
            test_tx_hash, tracer_type="callTracer", tracer_config={"withLog": True}
        )
        print("Call Trace:")
        # print(json.dumps(call_trace, indent=2)) # Requires json import

        # Example: Get prestate trace (if supported by node)
        # prestate_trace = collector.get_trace(test_tx_hash, tracer_type="prestateTracer")
        # print("\nPrestate Trace:")
        # print(json.dumps(prestate_trace, indent=2))

    except ValueError as ve:
        print(f"Trace collection failed: {ve}")
    except ConnectionError as ce:
        print(f"Connection failed: {ce}")
    except Exception as ex:
        print(f"An error occurred: {ex}")
