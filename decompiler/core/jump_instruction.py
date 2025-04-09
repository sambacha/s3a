from decompiler.core.instruction import Instruction

class JumpInstruction(Instruction):
    def __init__(self, offset, opcode, operands=None):
        super().__init__(offset, opcode, operands)
        self.classification = None  # 'intra-procedural', 'private-call', 'private-return'
        self.target_resolved = False
        self.targets = []  # Possible jump targets
        self.locally_resolved = False
        self.escaping_dest = False
