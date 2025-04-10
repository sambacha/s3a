from pyevmasm import disassemble_all, Instruction as PyevmInstruction
from decompiler.core.basic_block import BasicBlock
from decompiler.core.instruction import Instruction # Import custom Instruction
from .analysis.stack_analyzer import OPCODE_STACK_EFFECTS # Import stack effects
import sys # For debug printing

def get_instruction_size(instr: PyevmInstruction):
    """Safely get the size of an instruction, defaulting to 1."""
    try:
        # pyevmasm's size() includes the opcode byte itself
        size = instr.size()
        return size if size is not None else 1
    except Exception:
        return 1

def identify_basic_blocks(bytecode):
    """
    Parse bytecode and identify basic blocks.
    A new basic block starts at:
    1. The first instruction (offset 0).
    2. A JUMPDEST instruction.
    3. The instruction following a terminating instruction (JUMP, JUMPI, STOP, RETURN, REVERT, INVALID, SELFDESTRUCT).
    """
    print("[Debug] identify_basic_blocks called", file=sys.stderr) # Debug
    basic_blocks = {}
    try:
        # Use disassemble_all instead of disassemble
        raw_instructions = list(disassemble_all(bytecode))
        # print(f"[Debug] Raw instructions (disassemble_all): {raw_instructions}", file=sys.stderr) # Debug
    except Exception as e:
        print(f"Error disassembling bytecode: {e}", file=sys.stderr) # Debug
        return {} # Return empty if disassembly fails

    if not raw_instructions:
        print("[Debug] No raw instructions found.", file=sys.stderr) # Debug
        return {}

    # 1. Create custom instructions and map raw instructions by offset
    instructions = [] # List of custom Instruction objects
    instr_map_raw = {} # Map offset to raw instruction for size lookup
    offset_to_instruction = {} # Map offset to custom instruction

    for pyevm_instr in raw_instructions:
        # Expecting PyevmInstruction objects now
        if isinstance(pyevm_instr, PyevmInstruction):
            offset = pyevm_instr.pc # Trust the pc from pyevmasm
            custom_instr = Instruction(
                offset=offset,
                opcode=pyevm_instr.mnemonic, # Use mnemonic from pyevmasm as opcode
                operands=[pyevm_instr.operand] if pyevm_instr.operand is not None else []
            )
            instructions.append(custom_instr)
            instr_map_raw[offset] = pyevm_instr
            offset_to_instruction[offset] = custom_instr
        else:
             print(f"[Debug] Unexpected type in raw_instructions: {type(pyevm_instr)}", file=sys.stderr) # Debug


    if not instructions:
        print("[Debug] No custom instructions created.", file=sys.stderr) # Debug
        return {}
    # print(f"[Debug] Custom instructions created: {len(instructions)}", file=sys.stderr) # Debug

    # 2. Identify all potential block start offsets
    block_starts = {0}
    terminating_opcodes = {'JUMP', 'JUMPI', 'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT'}
    instruction_offsets = sorted(offset_to_instruction.keys()) # Get sorted list of valid instruction offsets
    # print(f"[Debug] Instruction offsets: {instruction_offsets}", file=sys.stderr) # Debug

    for offset in instruction_offsets:
        instr = offset_to_instruction[offset]
        if instr.opcode == 'JUMPDEST':
            block_starts.add(offset)

        raw_instr = instr_map_raw.get(offset)
        if raw_instr and instr.opcode in terminating_opcodes:
            next_offset = offset + get_instruction_size(raw_instr)
            # Only add if the next offset corresponds to an actual instruction start
            if next_offset in offset_to_instruction:
                block_starts.add(next_offset)

    sorted_block_starts = sorted(list(block_starts))
    # print(f"[Debug] Sorted block starts: {sorted_block_starts}", file=sys.stderr) # Debug

    # 3. Create Basic Blocks (Revised Logic 8 - Direct Range Filtering)
    num_starts = len(sorted_block_starts)
    for i, start_offset in enumerate(sorted_block_starts):
        # Determine the end offset for filtering (start of the next block)
        # Use the maximum possible offset if it's the last block start
        next_block_start_offset = sorted_block_starts[i+1] if i + 1 < num_starts else (instruction_offsets[-1] + 1 if instruction_offsets else 0)
        # print(f"[Debug] Block {i}: start={start_offset}, next_start={next_block_start_offset}", file=sys.stderr) # Debug

        # Filter instructions belonging strictly to this block's range
        block_instructions = [
            instr for instr in instructions
            if start_offset <= instr.offset < next_block_start_offset
        ]
        # print(f"[Debug] Block {i}: Filtered instructions count: {len(block_instructions)}", file=sys.stderr) # Debug

        if block_instructions:
            # The end_offset of the block is the offset of its last instruction
            actual_end_offset = block_instructions[-1].offset
            block = BasicBlock(start_offset=start_offset, end_offset=actual_end_offset)
            block.instructions = block_instructions
            basic_blocks[start_offset] = block
            # print(f"[Debug] Block {i}: Created block at offset {start_offset}", file=sys.stderr) # Debug
        # else:
            # print(f"[Debug] Block {i}: No instructions found for block starting at {start_offset}", file=sys.stderr) # Debug


    # 4. Identify Successors (Revised with Intra-Block Stack Sim)
    print(f"[Debug] Identifying successors for {len(basic_blocks)} blocks", file=sys.stderr) # Debug
    for start_offset, block in basic_blocks.items():
        if not block.instructions: continue

        # --- Intra-block stack simulation for JUMP/JUMPI ---
        simulated_stack = []
        possible_jump_target = None
        for instr in block.instructions:
            opcode = instr.opcode
            pops, pushes = 0, 0

            # Get stack effect
            if opcode.startswith("PUSH"):
                pops, pushes = 0, 1
                if instr.operands:
                     simulated_stack.append(instr.operands[0]) # Push the constant value
                else:
                     simulated_stack.append(None) # Cannot determine value
            elif opcode.startswith("DUP"):
                dup_n = int(opcode[3:])
                pops, pushes = 0, 1
                if len(simulated_stack) >= dup_n:
                    simulated_stack.append(simulated_stack[-dup_n])
                else:
                    simulated_stack.append(None) # Underflow
            elif opcode.startswith("SWAP"):
                swap_n = int(opcode[4:])
                pops, pushes = 0, 0
                if len(simulated_stack) >= swap_n + 1:
                    simulated_stack[-1], simulated_stack[-(swap_n + 1)] = simulated_stack[-(swap_n + 1)], simulated_stack[-1]
                # else: underflow, stack unchanged effectively for simulation
            elif opcode in OPCODE_STACK_EFFECTS:
                pops, pushes = OPCODE_STACK_EFFECTS[opcode]
            else: # Unknown opcode
                pops, pushes = 0, 0

            # Simulate stack operations
            # Pop first
            popped_values = []
            for _ in range(pops):
                if simulated_stack:
                    popped_values.append(simulated_stack.pop())
                else:
                    popped_values.append(None) # Underflow

            # Check for JUMP/JUMPI target
            if opcode == "JUMP" or opcode == "JUMPI":
                 target = popped_values[0] # Target is the first value popped
                 if isinstance(target, int):
                     possible_jump_target = target
                 # Stop simulation at jump
                 break

            # Push results (as None, since we only track constants for jumps)
            for _ in range(pushes):
                simulated_stack.append(None)


        # --- Add Successors ---
        last_instr = block.instructions[-1]
        raw_last_instr = instr_map_raw.get(last_instr.offset)

        # Add JUMP/JUMPI target if statically resolved via simulation
        if last_instr.opcode in ("JUMP", "JUMPI") and possible_jump_target is not None:
             if possible_jump_target in basic_blocks:
                 target_block = basic_blocks[possible_jump_target]
                 # Ensure the target is a JUMPDEST
                 if target_block.instructions and target_block.instructions[0].opcode == 'JUMPDEST':
                      if target_block not in block.successors:
                          block.successors.append(target_block)
                          print(f"[Debug] Added jump target successor {possible_jump_target} for block {start_offset}", file=sys.stderr) # Debug


        # Add fallthrough successor for JUMPI or non-terminating opcodes
        if raw_last_instr and last_instr.opcode not in ('JUMP', 'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT'):
            fallthrough_offset = last_instr.offset + get_instruction_size(raw_last_instr)
            if fallthrough_offset != -1 and fallthrough_offset in basic_blocks:
                 if basic_blocks[fallthrough_offset] not in block.successors:
                     block.successors.append(basic_blocks[fallthrough_offset])
                     print(f"[Debug] Added fallthrough successor {fallthrough_offset} for block {start_offset}", file=sys.stderr) # Debug


    # Add predecessors based on successors
    for start, block in basic_blocks.items():
        for successor in block.successors:
            if block not in successor.predecessors:
                 successor.predecessors.append(block)

    print(f"[Debug] identify_basic_blocks returning {len(basic_blocks)} blocks", file=sys.stderr) # Debug
    return basic_blocks
