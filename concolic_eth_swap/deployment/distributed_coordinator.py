# deployment/distributed_coordinator.py
import redis
import pickle
import json
import uuid
import time
from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger()


class DistributedTaskQueue:
    """Redis-based distributed task queue for concolic execution"""

    def __init__(self, redis_url="redis://localhost:6379/0"):
        try:
            self.redis = redis.from_url(
                redis_url, decode_responses=True
            )  # Decode responses to strings
            self.redis.ping()  # Check connection
            logger.info("Connected to Redis for task queue", url=redis_url)
        except redis.exceptions.ConnectionError as e:
            logger.error("Failed to connect to Redis", url=redis_url, error=str(e))
            raise ConnectionError(
                f"Could not connect to Redis at {redis_url}: {e}"
            ) from e

        self.task_queue = "concolic:tasks"  # List holding task IDs to be processed
        self.result_queue = (
            "concolic:results"  # List holding task IDs that are completed
        )
        self.processing_set = (
            "concolic:processing"  # Set holding task IDs currently being processed
        )
        self.task_hash_prefix = "concolic:task:"  # Prefix for hash storing task details (task_id -> task_data)
        self.poi_hash_prefix = (
            "concolic:poi:"  # Prefix for hash storing POI details (poi_id -> poi_data)
        )
        self.result_hash_prefix = "concolic:result:"  # Prefix for hash storing result details (task_id -> result_data)

    def enqueue_transaction(
        self, tx_hash: str, options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Enqueue a full transaction analysis task"""
        task_id = str(uuid.uuid4())
        options = options or {}

        task_data = {
            "id": task_id,
            "tx_hash": tx_hash,
            "options": json.dumps(options),  # Store options as JSON string
            "status": "pending",
            "created_at": time.time(),
        }

        task_key = f"{self.task_hash_prefix}{task_id}"
        logger.debug(
            "Enqueuing transaction task",
            task_id=task_id,
            tx_hash=tx_hash,
            task_key=task_key,
        )

        try:
            # Use a pipeline for atomicity
            with self.redis.pipeline() as pipe:
                pipe.hset(task_key, mapping=task_data)
                pipe.lpush(self.task_queue, task_id)  # Push task ID to the queue
                pipe.execute()
            logger.info(
                "Transaction task enqueued successfully",
                task_id=task_id,
                tx_hash=tx_hash,
            )
            return task_id
        except Exception as e:
            logger.exception(
                "Failed to enqueue transaction task",
                task_id=task_id,
                tx_hash=tx_hash,
                error=str(e),
            )
            raise  # Re-raise after logging

    def enqueue_points_of_interest(
        self,
        tx_hash: str,
        points_of_interest: List[Dict[str, Any]],
        parent_task_id: Optional[str] = None,
    ) -> List[str]:
        """Enqueue individual points of interest for analysis, potentially linked to a parent task"""
        poi_task_ids = []
        logger.debug(
            f"Enqueuing {len(points_of_interest)} points of interest for",
            tx_hash=tx_hash,
        )

        try:
            with self.redis.pipeline() as pipe:
                for i, poi in enumerate(points_of_interest):
                    poi_id = str(uuid.uuid4())
                    poi_task_id = f"poi:{poi_id}"  # Distinguish POI tasks in the queue

                    poi_data = {
                        "id": poi_id,
                        "tx_hash": tx_hash,
                        "parent_task_id": parent_task_id or "",
                        # Ensure basic POI fields exist
                        "poi_index": i,
                        "type": poi.get("type", "UNKNOWN"),
                        "from": poi.get("from", ""),
                        "to": poi.get("to", ""),
                        "input": poi.get("input", "0x"),
                        "value": poi.get("value", "0x0"),
                        "gas": poi.get("gas", "0x0"),
                        "call_depth": poi.get("call_depth", -1),
                        "status": "pending",
                        "created_at": time.time(),
                    }
                    poi_key = f"{self.poi_hash_prefix}{poi_id}"

                    # Store POI details
                    pipe.hset(
                        poi_key, mapping={k: str(v) for k, v in poi_data.items()}
                    )  # Store all as strings for simplicity
                    # Add POI task ID to the main task queue
                    pipe.lpush(self.task_queue, poi_task_id)
                    poi_task_ids.append(poi_id)

                pipe.execute()
            logger.info(
                f"Enqueued {len(poi_task_ids)} POI tasks",
                tx_hash=tx_hash,
                parent_task_id=parent_task_id,
            )
            return poi_task_ids
        except Exception as e:
            logger.exception(
                "Failed to enqueue POI tasks", tx_hash=tx_hash, error=str(e)
            )
            raise

    def get_next_task(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Atomically gets the next task ID from the queue and moves it to the processing set.
        Returns the task details (either full transaction or POI).
        Uses BRPOPLPUSH for atomicity (requires Redis >= 1.2).
        If using Redis Cluster or older versions, a Lua script or WATCH/MULTI/EXEC might be needed.
        """
        logger.debug("Waiting for next task", timeout=timeout)
        try:
            # Atomically pop from task_queue and push to a temporary processing list for this worker
            # This pattern is safer than BRPOP + SADD as it handles worker crashes.
            # However, jsonrpcserver is sync, so blocking might be okay. Let's use BRPOP + SADD for simplicity first.

            result = self.redis.brpop(self.task_queue, timeout=timeout)
            if not result:
                logger.debug("No task received within timeout")
                return None

            queue_name, task_identifier = result  # queue_name is self.task_queue
            task_identifier = task_identifier  # Already decoded by redis-py setting

            logger.info(
                "Received task identifier from queue", task_identifier=task_identifier
            )

            # Add to processing set *after* retrieving
            self.redis.sadd(self.processing_set, task_identifier)

            # Retrieve task details based on identifier type
            if task_identifier.startswith("poi:"):
                poi_id = task_identifier[4:]
                poi_key = f"{self.poi_hash_prefix}{poi_id}"
                poi_data = self.redis.hgetall(poi_key)
                if not poi_data:
                    logger.error(
                        "POI data not found in Redis hash after retrieving ID",
                        poi_id=poi_id,
                        key=poi_key,
                    )
                    self.redis.srem(
                        self.processing_set, task_identifier
                    )  # Clean up processing set
                    return None  # Skip this task

                # Update status
                self.redis.hset(poi_key, "status", "processing")
                logger.debug("Retrieved POI task details", poi_id=poi_id)
                return {"type": "poi", "id": poi_id, "data": poi_data}
            else:
                # Full transaction task
                task_id = task_identifier
                task_key = f"{self.task_hash_prefix}{task_id}"
                task_data = self.redis.hgetall(task_key)
                if not task_data:
                    logger.error(
                        "Task data not found in Redis hash after retrieving ID",
                        task_id=task_id,
                        key=task_key,
                    )
                    self.redis.srem(self.processing_set, task_identifier)  # Clean up
                    return None  # Skip

                # Update status
                self.redis.hset(task_key, "status", "processing")
                logger.debug("Retrieved transaction task details", task_id=task_id)
                # Decode options string
                if "options" in task_data:
                    try:
                        task_data["options"] = json.loads(task_data["options"])
                    except json.JSONDecodeError:
                        logger.warning(
                            "Failed to decode options JSON for task", task_id=task_id
                        )
                        task_data["options"] = {}  # Default to empty dict
                return {"type": "transaction", "id": task_id, "data": task_data}

        except redis.exceptions.ConnectionError as e:
            logger.error("Redis connection error during get_next_task", error=str(e))
            # Depending on strategy, might try to reconnect or raise
            raise
        except Exception as e:
            logger.exception("Error getting next task from queue", error=str(e))
            # If task_identifier was retrieved but details failed, try to remove from processing?
            # This part needs careful error handling strategy.
            return None

    def report_result(
        self, task_identifier: str, result: Dict[str, Any], status: str = "completed"
    ):
        """Report task execution result and update status."""
        logger.debug(
            "Reporting result for task", task_identifier=task_identifier, status=status
        )
        try:
            result_key = f"{self.result_hash_prefix}{task_identifier}"
            result_data = {
                "task_identifier": task_identifier,
                "status": status,
                "result": json.dumps(result),  # Store result as JSON string
                "completed_at": time.time(),
            }

            # Determine original task key
            if task_identifier.startswith("poi:"):
                task_key = f"{self.poi_hash_prefix}{task_identifier[4:]}"
            else:
                task_key = f"{self.task_hash_prefix}{task_identifier}"

            with self.redis.pipeline() as pipe:
                # Store result
                pipe.hset(result_key, mapping=result_data)
                # Update original task status
                pipe.hset(task_key, "status", status)
                # Remove from processing set
                pipe.srem(self.processing_set, task_identifier)
                # Add to result notification queue (optional)
                pipe.lpush(self.result_queue, task_identifier)
                pipe.execute()

            logger.info(
                "Task result reported successfully",
                task_identifier=task_identifier,
                status=status,
            )

        except Exception as e:
            logger.exception(
                "Failed to report task result",
                task_identifier=task_identifier,
                error=str(e),
            )
            # Consider retry logic or marking task as failed to report

    def get_task_result(
        self, task_identifier: str, wait: bool = False, timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        """Get task result, optionally waiting for completion."""
        logger.debug(
            "Getting task result",
            task_identifier=task_identifier,
            wait=wait,
            timeout=timeout,
        )
        start_time = time.time()
        result_key = f"{self.result_hash_prefix}{task_identifier}"

        while True:
            try:
                result_data = self.redis.hgetall(result_key)

                if result_data:
                    logger.debug("Found result data", task_identifier=task_identifier)
                    # Decode result JSON
                    if "result" in result_data:
                        try:
                            result_data["result"] = json.loads(result_data["result"])
                        except json.JSONDecodeError:
                            logger.warning(
                                "Failed to decode result JSON",
                                task_identifier=task_identifier,
                            )
                            result_data["result"] = {
                                "error": "Failed to decode result JSON"
                            }
                    return result_data

                if not wait or (time.time() - start_time) > timeout:
                    logger.debug(
                        "Result not found or timeout reached",
                        task_identifier=task_identifier,
                    )
                    return None

                # Wait a bit before checking again
                logger.debug(
                    "Result not found yet, waiting...", task_identifier=task_identifier
                )
                time.sleep(0.5)

            except redis.exceptions.ConnectionError as e:
                logger.error(
                    "Redis connection error during get_task_result", error=str(e)
                )
                raise
            except Exception as e:
                logger.exception(
                    "Error getting task result",
                    task_identifier=task_identifier,
                    error=str(e),
                )
                return None  # Return None on error


# Example usage (illustrative)
if __name__ == "__main__":
    logger.info("Running DistributedTaskQueue example")
    try:
        queue = DistributedTaskQueue()

        # Enqueue a task
        opts = {"max_depth": 500}
        task_id = queue.enqueue_transaction("0x12345...", options=opts)
        print(f"Enqueued task: {task_id}")

        # Simulate a worker getting the task
        print("Worker waiting for task...")
        worker_task = queue.get_next_task(timeout=10)
        if worker_task:
            print(f"Worker received task: {worker_task['id']}")
            # Simulate processing
            time.sleep(2)
            # Simulate result
            task_result = {"is_swap": True, "details": {"type": "ETH_TO_USDC"}}
            queue.report_result(worker_task["id"], task_result, status="completed")
            print(f"Worker reported result for task: {worker_task['id']}")
        else:
            print("Worker timed out.")

        # Check result
        print(f"Checking result for task {task_id}...")
        final_result = queue.get_task_result(task_id, wait=True, timeout=5)
        if final_result:
            print(f"Retrieved result: {final_result}")
        else:
            print("Result not found.")

    except ConnectionError as e:
        print(f"Redis connection error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
