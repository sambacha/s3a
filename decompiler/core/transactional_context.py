class TransactionalContext:
    def __init__(self, public_func=None, private_ctx=None):
        self.public_func = public_func
        self.private_ctx = private_ctx or []
        self.max_private_depth = 8  # Configurable depth
        
    def merge(self, call):
        # Implement merging logic from the specification
        if call not in self.private_ctx and len(self.private_ctx) < self.max_private_depth:
            self.private_ctx.append(call)
