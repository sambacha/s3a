class Function:
    def __init__(self, entry_block):
        self.entry_block = entry_block
        self.exit_blocks = []
        self.blocks = set()
        self.calls = []  # Outgoing calls
        self.callers = []  # Incoming calls
        self.args = 0  # Number of arguments
        self.returns = 0  # Number of return values
