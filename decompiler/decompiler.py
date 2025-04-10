from .disassembler import identify_basic_blocks, instr_map_raw # Assuming instr_map_raw is accessible or passed back
from .analysis.stack_analyzer import analyze_stack_locally
from .analysis.jump_classifier import classify_jumps
from .analysis.context_builder import create_context
from .analysis.function_boundary import infer_function_boundaries
from .analysis.argument_inference import infer_function_arguments
from .analysis.symbolic_executor import SymbolicExecutor, ExecutionState # Import symbolic execution components
import sys # For debug printing

class SmartContractDecompiler:
    def __init__(self, bytecode):
        self.bytecode = bytecode
        # Pass instr_map_raw back or make it accessible if needed by executor
        self.basic_blocks = identify_basic_blocks(bytecode)
        # Need instr_map_raw for SymbolicExecutor
        # TODO: Refactor identify_basic_blocks to return instr_map_raw or make it global/class member?
        # For now, assume instr_map_raw is available globally or passed differently.
        # Let's re-run disassembly partially to get it for now (inefficient)
        try:
            temp_raw_instr = list(disassemble_all(bytecode))
            temp_instr_map_raw = {instr.pc: instr for instr in temp_raw_instr if isinstance(instr, PyevmInstruction)}
        except:
            temp_instr_map_raw = {}


        print(f"[Decompiler Init] Basic blocks identified: {len(self.basic_blocks)}", file=sys.stderr)

        for block in self.basic_blocks.values():
            analyze_stack_locally(block)

        self.jumps = {
            instr.offset: instr # Use offset from custom Instruction
            for block in self.basic_blocks.values()
            for instr in block.instructions
            if instr.opcode in ("JUMP", "JUMPI") # Use opcode
        }
        print(f"[Decompiler Init] Jumps found: {len(self.jumps)}", file=sys.stderr)


        # --- Step 3: Analyze Jumps Symbolically ---
        jump_analysis_results = {}
        if self.basic_blocks and temp_instr_map_raw: # Check if blocks and map exist
             symbolic_executor = SymbolicExecutor(self.basic_blocks, temp_instr_map_raw)
             print("[Decompiler Init] Analyzing jumps...", file=sys.stderr)
             for jump_offset, jump_instr in self.jumps.items():
                 # Find the block containing the jump
                 # This assumes jump_offset is the start of a block if the jump is the first instr,
                 # or we need to find which block contains this offset.
                 containing_block = None
                 for block_start, block in self.basic_blocks.items():
                      # Check if jump_offset is within the block's instruction offsets
                      instr_offsets = [instr.offset for instr in block.instructions]
                      if jump_offset in instr_offsets:
                           containing_block = block
                           break

                 if containing_block:
                     # Define a default initial state for the block entry
                     # TODO: This needs proper state propagation from predecessors
                     initial_state = ExecutionState(pc=containing_block.start_offset, stack=[])
                     print(f"[Decompiler Init] Analyzing jump at {hex(jump_offset)} in block {containing_block.start_offset}", file=sys.stderr)

                     try:
                         concrete_target, symbolic_target_expr = symbolic_executor.analyze_jump(jump_instr, initial_state)
                         print(f"[Decompiler Init] Jump {hex(jump_offset)} -> Concrete: {hex(concrete_target) if concrete_target is not None else None}, Symbolic: {symbolic_target_expr}", file=sys.stderr)

                         # Determine properties based on symbolic analysis result
                         is_resolved = concrete_target is not None
                         is_unique = concrete_target is not None # Simplification
                         is_escaping = False # Placeholder - needs function boundary info

                         jump_analysis_results[jump_offset] = {
                             'locally_resolved': is_resolved,
                             'unique_target': is_unique,
                             'escaping_dest': is_escaping,
                             'concrete_target': concrete_target # Store for potential use
                         }
                     except Exception as e:
                          print(f"[Error] Symbolic execution for jump {hex(jump_offset)} failed: {e}", file=sys.stderr)
                          jump_analysis_results[jump_offset] = {
                             'locally_resolved': False, 'unique_target': False, 'escaping_dest': False, 'concrete_target': None
                          }

                 else:
                      print(f"[Warning] Could not find block containing jump at {hex(jump_offset)}", file=sys.stderr)
                      jump_analysis_results[jump_offset] = {
                         'locally_resolved': False, 'unique_target': False, 'escaping_dest': False, 'concrete_target': None
                      }
        else:
             print("[Warning] Cannot perform jump analysis: No basic blocks or instruction map.", file=sys.stderr)


        self.cfg = {}  # Control Flow Graph (Can be built using block successors)
        self.contexts = {}  # Context tracking for analysis

        # --- Step 4: Classify Jumps using Z3 ---
        print("[Decompiler Init] Classifying jumps...", file=sys.stderr)
        try:
            # Pass the analysis results to classify_jumps
            self.jump_classifications = classify_jumps(
                self.jumps, self.basic_blocks, jump_analysis_results # Pass analysis results
            )
            print(f"[Decompiler Init] Jump Classifications: {self.jump_classifications}", file=sys.stderr)
        except Exception as e:
             print(f"[Error] Jump classification failed: {e}", file=sys.stderr)
             self.jump_classifications = {} # Default empty on error


        # --- Step 5: Infer Function Boundaries ---
        print("[Decompiler Init] Inferring function boundaries...", file=sys.stderr)
        # TODO: The stack_analysis_results might still be needed here depending on final implementation
        # Pass jump_classifications now
        self.functions = infer_function_boundaries(
            self.jumps,
            self.basic_blocks,
            self.jump_classifications,
            {}, # Pass empty dict for now instead of stack_analysis_results
        )
        print(f"[Decompiler Init] Functions inferred: {len(self.functions)}", file=sys.stderr)


        # --- Step 6: Infer Function Arguments ---
        print("[Decompiler Init] Inferring function arguments...", file=sys.stderr)
        for func_offset, function in self.functions.items():
             # Pass only the function and all blocks, as stack info is now in blocks
             if function: # Ensure function object is valid
                 infer_function_arguments(function, self.basic_blocks)
                 print(f"[Decompiler Init] Function {hex(func_offset)}: Args={function.args}, Returns={function.returns}", file=sys.stderr)


        # --- Step 7: Context Sensitivity (Placeholder) ---
        # print("[Decompiler Init] Building contexts (placeholder)...", file=sys.stderr)
        # for instr_offset in offset_to_instruction:
        #     instr = offset_to_instruction[instr_offset]
        #     # This needs proper CFG traversal and state management
        #     # self.contexts[instr.offset] = create_context(instr, {}, self.jump_classifications) # Use offset
