# core/concolic.py
from typing import Dict, List, Optional, Any, Tuple
import time
import structlog
from .symbolic import (
    SymbolicExecutor,
    SymbolicEVMState,
    SymbolicValue,
    PathConstraint,
    Z3SolverContext,
    SymbolicType,
)
from .concrete import ConcreteExecutor
import z3  # Needed for Z3 operations in swap checks

logger = structlog.get_logger()

# Default minimum swap amount (can be made configurable)
# Represented as a symbolic variable to allow flexibility if needed
MIN_SWAP_AMOUNT_NAME = "min_swap_amount"
DEFAULT_MIN_SWAP_THRESHOLD = 1  # Minimal non-zero value to avoid dust


class ConcolicExecutor:
    def __init__(self, web3_provider_url: str, network: str = "mainnet"):
        # Initialize concrete executor with network info
        self.concrete_executor = ConcreteExecutor(web3_provider_url, network)
        # Symbolic executor uses its own Z3 context internally
        self.symbolic_executor = SymbolicExecutor()
        self.network = network  # Store network for context

        # Add min_swap_amount to the solver context early
        self.symbolic_executor.solver_context.get_or_create_var(
            MIN_SWAP_AMOUNT_NAME, 256
        )
        # Optionally, add a default constraint for it (can be overridden)
        # self.symbolic_executor.solver_context.solver.add(
        #     self.symbolic_executor.solver_context.variables[MIN_SWAP_AMOUNT_NAME] >= DEFAULT_MIN_SWAP_THRESHOLD
        # )

    def analyze_transaction(
        self,
        tx_hash: str,
        max_poi=10,
        timeout_seconds=30,
        max_sym_paths=5,
        max_sym_depth=100,
    ):
        """Main entry point for concolic analysis of a transaction"""
        start_time = time.time()
        logger.info(
            "Starting concolic analysis",
            tx_hash=tx_hash,
            timeout=timeout_seconds,
            max_poi=max_poi,
        )

        try:
            # 1. Get transaction details and initial context
            tx = self.concrete_executor.get_transaction_details(tx_hash)
            receipt = self.concrete_executor.get_transaction_receipt(
                tx_hash
            )  # Needed for status, logs
            block_context = self.concrete_executor.get_block_context(tx["blockNumber"])
            contract_address = tx.get("to")
            if not contract_address:
                # Contract creation transaction - analysis might differ
                logger.warning(
                    "Contract creation transaction detected, swap analysis might be limited.",
                    tx_hash=tx_hash,
                )
                # Use receipt's contractAddress if available
                contract_address = receipt.get("contractAddress")
                if not contract_address:
                    return self._format_result(
                        tx_hash,
                        start_time,
                        False,
                        {},
                        error="Contract creation TX without address",
                    )

            contract_code = self.concrete_executor.get_contract_code(contract_address)

            # 2. Execute concretely to identify points of interest
            trace = self.concrete_executor.trace_transaction(tx_hash)
            points_of_interest = self.concrete_executor.extract_points_of_interest(
                trace
            )
            logger.info(
                f"Found {len(points_of_interest)} potential points of interest",
                tx_hash=tx_hash,
            )

            # 3. Focus symbolic execution starting from these points
            swap_results = []
            analyzed_poi_count = 0
            for i, poi in enumerate(points_of_interest):
                if analyzed_poi_count >= max_poi:
                    logger.info("Reached max points of interest limit", limit=max_poi)
                    break

                # Check timeout
                if time.time() - start_time > timeout_seconds:
                    logger.warning(
                        "Timeout reached during concolic analysis", tx_hash=tx_hash
                    )
                    return self._format_result(
                        tx_hash, start_time, False, {}, error="Timeout reached"
                    )

                logger.info(
                    f"Analyzing point of interest {i + 1}/{len(points_of_interest)}",
                    tx_hash=tx_hash,
                    poi_target=poi.get("to"),
                )
                analyzed_poi_count += 1

                # Prepare initial symbolic state based on concrete trace up to the POI
                # This is complex: needs to reconstruct stack/memory/storage symbolically
                # For now, we simplify: start symbolic execution from the beginning,
                # but use POI information to guide analysis or focus checks.
                # A more advanced approach would snapshot concrete state at POI and make inputs symbolic.

                # Simplified approach: Run full symbolic execution once
                # In a real system, we'd run symbolic execution *from* each POI or use
                # the POI to guide a single, deeper symbolic run.
                # Let's stick to the plan's idea of analyzing paths from a single run for now.

                # Initialize symbolic state for the *entire* transaction
                init_state = self.symbolic_executor.initialize_state(
                    tx, block_context, contract_code, contract_address
                )

                # Add concrete balance constraints (optional, but helps ground analysis)
                # self._add_initial_balance_constraints(init_state, tx)

                # Execute symbolically for the whole transaction
                # We only need to do this once if analyzing paths post-execution
                paths = self.symbolic_executor.execute_symbolic(
                    tx,
                    block_context,
                    contract_code,
                    contract_address,
                    max_paths=max_sym_paths,
                    max_depth=max_sym_depth,
                )

                # Analyze all resulting paths for swap patterns
                for path_state, termination_reason in paths:
                    if (
                        termination_reason.startswith("error:")
                        or termination_reason == "symbolic_pc"
                    ):
                        continue  # Skip errored or unprocessable paths

                    # Check this specific path for ETH/USDC swap pattern
                    swap_info = self._check_swap_balance_pattern(path_state, tx["from"])
                    if swap_info and swap_info["is_swap"]:
                        logger.info(
                            "Swap pattern detected in symbolic path",
                            tx_hash=tx_hash,
                            details=swap_info,
                        )
                        swap_results.append(swap_info)
                        # Optional: Stop after first swap found? Or collect all? Collect all for now.

                # Since we run symbolic execution once, break after analyzing its paths
                break  # Remove this if running symbolic exec per POI

        except Exception as e:
            logger.exception(
                "Error during concolic analysis", tx_hash=tx_hash, error=str(e)
            )
            return self._format_result(tx_hash, start_time, False, {}, error=str(e))

        # 4. Aggregate and analyze results
        final_result = self._aggregate_results(swap_results)
        return self._format_result(tx_hash, start_time, True, final_result)

    def _format_result(
        self, tx_hash, start_time, analysis_complete, swap_data, error=None
    ):
        """Helper to format the final analysis result"""
        execution_time = time.time() - start_time
        result = {
            "tx_hash": tx_hash,
            "analysis_complete": analysis_complete and error is None,
            "execution_time": round(execution_time, 3),
            "is_swap": swap_data.get("is_swap", False),
            "swap_details": swap_data.get("details", {}) if swap_data else {},
        }
        if error:
            result["error"] = error
        logger.info("Concolic analysis finished", **result)
        return result

    # Placeholder: Add constraints based on concrete initial balances
    # def _add_initial_balance_constraints(self, state: SymbolicEVMState, tx: Dict):
    #     sender = tx['from']
    #     try:
    #         # Get balances *before* the transaction block
    #         block_num = tx.get('blockNumber')
    #         prev_block = block_num - 1 if block_num is not None and block_num > 0 else 'latest' # Approximation
    #
    #         eth_balance = self.concrete_executor.get_eth_balance(sender, prev_block)
    #         usdc_address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" # TODO: Get from config
    #         # usdc_balance = self.concrete_executor.get_token_balance(usdc_address, sender, prev_block) # Needs ABI
    #         usdc_balance = 0 # Placeholder
    #
    #         eth_sym = state.token_balances.get("ETH", {}).get(sender)
    #         usdc_sym = state.token_balances.get(usdc_address, {}).get(sender)
    #
    #         if eth_sym:
    #             constraint = (eth_sym == eth_balance) # Creates a symbolic comparison value
    #             state.path_constraints.append(PathConstraint(condition=constraint, taken=True))
    #             logger.debug("Added concrete ETH balance constraint", address=sender, balance=eth_balance)
    #         if usdc_sym:
    #             constraint = (usdc_sym == usdc_balance)
    #             state.path_constraints.append(PathConstraint(condition=constraint, taken=True))
    #             logger.debug("Added concrete USDC balance constraint", address=sender, balance=usdc_balance)
    #
    #     except Exception as e:
    #         logger.warning("Failed to get or add initial balance constraints", error=str(e))

    # This function was part of the plan but is complex to implement correctly without
    # full state reconstruction at POI. Sticking to full tx analysis for now.
    # def _prepare_symbolic_state(self, tx, poi, trace): ...

    def _aggregate_results(self, results: List[Dict]) -> Dict:
        """Aggregate results from multiple paths or POIs"""
        if not results:
            return {"is_swap": False}

        # Simple aggregation: return the first detected swap
        # More complex logic could merge details or score confidence
        first_swap = results[0]
        return {
            "is_swap": True,
            "details": first_swap,  # Return details of the first swap found
        }

    def _check_swap_balance_pattern(
        self, state: SymbolicEVMState, sender: str
    ) -> Optional[Dict]:
        """Check if token balance changes in a given state follow a swap pattern"""
        logger.debug("Checking swap balance pattern", sender=sender)
        eth_addr = "ETH"
        usdc_addr = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"  # TODO: Get from config/patterns

        # Get symbolic values for initial and final balances from the state's perspective
        # Note: 'initial' here means the symbolic variable created at the start of execution
        initial_eth_sym = self.symbolic_executor.create_symbolic_variable(
            f"initial_eth_balance_{sender}"
        )
        initial_usdc_sym = self.symbolic_executor.create_symbolic_variable(
            f"initial_usdc_balance_{sender}"
        )

        # Final balances are the current values in the state
        final_eth = state.token_balances.get(eth_addr, {}).get(sender)
        final_usdc = state.token_balances.get(usdc_addr, {}).get(sender)

        if not final_eth or not final_usdc:
            logger.debug(
                "Final ETH or USDC balance not found in state for sender", sender=sender
            )
            return {"is_swap": False}

        # Use the solver context associated with this executor
        solver_ctx = self.symbolic_executor.solver_context
        solver = solver_ctx.solver

        # Check patterns within the context of the path's constraints
        solver.push()
        for constraint in state.path_constraints:
            try:
                solver.add(constraint.to_z3(solver_ctx))
            except Exception as e:
                logger.error(
                    "Failed to add path constraint to solver",
                    constraint=constraint,
                    error=str(e),
                )
                solver.pop()
                return {"is_swap": False, "error": "Constraint processing failed"}

        # Check ETH -> USDC
        eth_to_usdc_details = self._check_eth_to_usdc_pattern(
            solver, solver_ctx, initial_eth_sym, initial_usdc_sym, final_eth, final_usdc
        )

        # Check USDC -> ETH
        usdc_to_eth_details = self._check_usdc_to_eth_pattern(
            solver, solver_ctx, initial_eth_sym, initial_usdc_sym, final_eth, final_usdc
        )

        solver.pop()  # Clean up solver state

        if eth_to_usdc_details:
            return {
                "is_swap": True,
                "swap_type": "ETH_TO_USDC",
                "details": eth_to_usdc_details,
            }
        elif usdc_to_eth_details:
            return {
                "is_swap": True,
                "swap_type": "USDC_TO_ETH",
                "details": usdc_to_eth_details,
            }

        return {"is_swap": False}

    def _check_eth_to_usdc_pattern(
        self,
        solver: z3.Solver,
        context: Z3SolverContext,
        initial_eth: SymbolicValue,
        initial_usdc: SymbolicValue,
        final_eth: SymbolicValue,
        final_usdc: SymbolicValue,
    ) -> Optional[Dict]:
        """Check for ETH to USDC swap pattern using Z3"""
        solver.push()
        try:
            i_eth = initial_eth.to_z3(context)
            i_usdc = initial_usdc.to_z3(context)
            f_eth = final_eth.to_z3(context)
            f_usdc = final_usdc.to_z3(context)
            min_swap_amount_var = context.get_or_create_var(MIN_SWAP_AMOUNT_NAME, 256)

            # Add constraints for the pattern:
            # 1. ETH balance decreases: final_eth < initial_eth
            solver.add(z3.ULT(f_eth, i_eth))
            # 2. USDC balance increases: final_usdc > initial_usdc
            solver.add(z3.UGT(f_usdc, i_usdc))
            # 3. Significant ETH decrease (more than minimum threshold)
            eth_decrease = i_eth - f_eth
            solver.add(z3.UGT(eth_decrease, min_swap_amount_var))
            # Optional: Add constraint for the default threshold if needed
            solver.add(z3.UGE(min_swap_amount_var, DEFAULT_MIN_SWAP_THRESHOLD))

            # Check if this scenario is possible under current path constraints
            result = solver.check()
            logger.debug(
                "Checking ETH->USDC pattern satisfiability", result=str(result)
            )

            if result == z3.sat:
                model = solver.model()
                eth_decrease_val = model.eval(
                    eth_decrease, model_completion=True
                ).as_long()
                usdc_increase_val = model.eval(
                    f_usdc - i_usdc, model_completion=True
                ).as_long()

                details = {
                    "eth_spent": str(eth_decrease_val),  # Use strings for large numbers
                    "usdc_received": str(usdc_increase_val),
                    "effective_price": f"{usdc_increase_val / eth_decrease_val:.18f}"
                    if eth_decrease_val > 0
                    else "N/A",
                }
                solver.pop()
                return details

        except Exception as e:
            logger.exception("Error checking ETH->USDC pattern", error=str(e))
        finally:
            # Ensure solver state is popped even if errors occur
            # Check if the push was successful before popping? Z3 might handle nested pops.
            # Popping here might interfere if called within another push/pop block.
            # Let the caller manage the main push/pop.
            # solver.pop() # Removed - caller manages push/pop
            pass  # Let finally clause ensure exit

        solver.pop()  # Pop the pattern check constraints
        return None

    def _check_usdc_to_eth_pattern(
        self,
        solver: z3.Solver,
        context: Z3SolverContext,
        initial_eth: SymbolicValue,
        initial_usdc: SymbolicValue,
        final_eth: SymbolicValue,
        final_usdc: SymbolicValue,
    ) -> Optional[Dict]:
        """Check for USDC to ETH swap pattern using Z3"""
        solver.push()
        try:
            i_eth = initial_eth.to_z3(context)
            i_usdc = initial_usdc.to_z3(context)
            f_eth = final_eth.to_z3(context)
            f_usdc = final_usdc.to_z3(context)
            min_swap_amount_var = context.get_or_create_var(MIN_SWAP_AMOUNT_NAME, 256)

            # Add constraints for the pattern:
            # 1. USDC balance decreases: final_usdc < initial_usdc
            solver.add(z3.ULT(f_usdc, i_usdc))
            # 2. ETH balance increases: final_eth > initial_eth
            solver.add(z3.UGT(f_eth, i_eth))
            # 3. Significant USDC decrease
            usdc_decrease = i_usdc - f_usdc
            solver.add(z3.UGT(usdc_decrease, min_swap_amount_var))
            # Optional: Add constraint for the default threshold
            solver.add(z3.UGE(min_swap_amount_var, DEFAULT_MIN_SWAP_THRESHOLD))

            result = solver.check()
            logger.debug(
                "Checking USDC->ETH pattern satisfiability", result=str(result)
            )

            if result == z3.sat:
                model = solver.model()
                usdc_decrease_val = model.eval(
                    usdc_decrease, model_completion=True
                ).as_long()
                eth_increase_val = model.eval(
                    f_eth - i_eth, model_completion=True
                ).as_long()

                details = {
                    "usdc_spent": str(usdc_decrease_val),
                    "eth_received": str(eth_increase_val),
                    "effective_price": f"{eth_increase_val / usdc_decrease_val:.18f}"
                    if usdc_decrease_val > 0
                    else "N/A",
                }
                solver.pop()
                return details

        except Exception as e:
            logger.exception("Error checking USDC->ETH pattern", error=str(e))
        finally:
            # Let caller manage push/pop
            pass

        solver.pop()
        return None
