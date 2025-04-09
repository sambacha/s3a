class Instruction:
    def __init__(self, offset, opcode, operands=None):
        self.offset = offset
        self.opcode = opcode
        self.operands = operands or []
        self.stack_in = []  # Stack state before execution
        self.stack_out = []  # Stack state after execution
