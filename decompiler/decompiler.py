from decompiler.disassembler import identify_basic_blocks, instr_map_raw # Assuming instr_map_raw is accessible or passed back
from decompiler.analysis.stack_analyzer import analyze_stack_locally
from decompiler.analysis.jump_classifier import classify_jumps
from decompiler.analysis.context_builder import create_context
from decompiler.analysis.function_boundary import infer_function_boundaries
# Removed duplicate relative imports that followed
from decompiler.analysis.argument_inference import infer_function_arguments
from decompiler.analysis.symbolic_executor import SymbolicExecutor, ExecutionState # Import symbolic execution components
import sys # For debug printing

class SmartContractDecompiler:
    def __init__(self, bytecode):
        self.bytecode = bytecode
        # Get both blocks and the instruction map from the updated function
        self.basic_blocks, self.instr_map_raw = identify_basic_blocks(bytecode)

        print(f"[Decompiler Init] Basic blocks identified: {len(self.basic_blocks)}", file=sys.stderr)
        print(f"[Decompiler Init] Raw instruction map size: {len(self.instr_map_raw)}", file=sys.stderr)

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
        if self.basic_blocks and self.instr_map_raw: # Use the map returned by identify_basic_blocks
             symbolic_executor = SymbolicExecutor(self.basic_blocks, self.instr_map_raw) # Pass the map here
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
                     # --- Estimate initial state (Placeholder for proper dataflow analysis) ---
                     # Try to estimate required stack depth based on local analysis
                     # min_stack_level is negative if block requires items (e.g., -2 means needs 2 items)
                     required_stack_depth = getattr(containing_block, 'min_stack_level', 0)
                     if required_stack_depth < 0:
                         required_stack_depth = abs(required_stack_depth)
                     else: # Block doesn't pop more than it pushes initially, 0 depth might be ok
                         required_stack_depth = 0

                     # Create a symbolic stack (approximation)
                     # TODO: This is an approximation. Proper dataflow analysis is needed
                     #       to determine the actual stack contents entering the block by merging
                     #       states from all predecessors.
                     initial_stack = [
                         symbolic_executor.create_symbolic_variable(f"stack_in_{containing_block.start_offset}_{i}")
                         for i in range(required_stack_depth)
                     ]
                     initial_state = ExecutionState(pc=containing_block.start_offset, stack=initial_stack)
                     # --- End Placeholder ---

                     print(f"[Decompiler Init] Analyzing jump at {hex(jump_offset)} in block {containing_block.start_offset} (Initial stack depth approx: {len(initial_stack)})", file=sys.stderr)

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


        # --- Step 7: Context Sensitivity ---
        print("[Decompiler Init] Building contexts...", file=sys.stderr)
        # Traverse the CFG to build contexts
        self.contexts = {}
        
        # Start with entry points (function starts)
        worklist = []
        visited = set()
        
        # Add function entry points to worklist
        for func_offset, function in self.functions.items():
            if function and function.entry_block:
                entry_offset = function.entry_block.start_offset
                worklist.append((entry_offset, {}))  # (block_offset, context)
        
        # Add main entry point (offset 0)
        if 0 in self.basic_blocks:
            worklist.append((0, {}))
            
        # Process the worklist
        while worklist:
            block_offset, current_context = worklist.pop()
            
            if block_offset in visited:
                continue
                
            visited.add(block_offset)
            block = self.basic_blocks.get(block_offset)
            
            if not block:
                continue
                
            # Process each instruction in the block
            for instr in block.instructions:
                # Create context for this instruction
                new_context = create_context(instr, current_context, self.jump_classifications)
                self.contexts[instr.offset] = new_context
                current_context = new_context
                
            # Add successors to worklist
            for succ in block.successors:
                if succ.start_offset not in visited:
                    # Check if this is a function call (don't follow call edges for context building)
                    is_call_edge = False
                    last_instr = block.instructions[-1] if block.instructions else None
                    
                    if last_instr and last_instr.offset in self.jump_classifications:
                        if self.jump_classifications[last_instr.offset] == "private-call":
                            is_call_edge = True
                    
                    if not is_call_edge:
                        worklist.append((succ.start_offset, current_context))
                        
        print(f"[Decompiler Init] Built contexts for {len(self.contexts)} instructions", file=sys.stderr)
