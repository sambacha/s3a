class BasicBlock:
    def __init__(self, start_offset, end_offset):
        self.id = f"block_{start_offset}"
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.instructions = []
        self.predecessors = []
        self.successors = []
        self.stack_height_in = None
        self.stack_height_out = None
        self.stack_effect = None  # (pushes, pops)
