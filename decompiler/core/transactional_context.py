from typing import Dict, Any, List, Optional, Union

class TransactionalContext:
    """
    Provides a context for tracking transactions across function boundaries.
    Enhanced to support a general key-value store and function call depth management.
    """
    def __init__(self, public_func=None, private_ctx=None, data=None):
        self.public_func = public_func
        self.private_ctx = private_ctx or []
        self.max_private_depth = 8  # Configurable depth
        self._data = data or {}      # Key-value store for context data
        self._call_depth = 0         # Current function call depth
    
    def clone(self) -> 'TransactionalContext':
        """Create a deep copy of this context."""
        new_ctx = TransactionalContext(
            public_func=self.public_func,
            private_ctx=self.private_ctx.copy(),
            data={k: v for k, v in self._data.items()}  # Copy the data dictionary
        )
        new_ctx._call_depth = self._call_depth
        return new_ctx
    
    def merge(self, call) -> None:
        """
        Add a call to the private context stack.
        
        Args:
            call: Call identifier to add
        """
        if (call not in self.private_ctx
            and len(self.private_ctx) < self.max_private_depth):
            self.private_ctx.append(call)
    
    def set(self, key: str, value: Any) -> None:
        """
        Store a value in the context.
        
        Args:
            key: The key to store the value under
            value: The value to store
        """
        self._data[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from the context.
        
        Args:
            key: The key to look up
            default: Value to return if key doesn't exist
            
        Returns:
            The stored value or default
        """
        return self._data.get(key, default)
    
    def enter_function(self) -> None:
        """Increment the function call depth."""
        self._call_depth += 1
        if self._call_depth > self.max_private_depth:
            # Prevent unbounded depth growth
            self._call_depth = self.max_private_depth
    
    def exit_function(self) -> None:
        """Decrement the function call depth."""
        self._call_depth -= 1
        if self._call_depth < 0:
            # Prevent negative depth
            self._call_depth = 0
    
    def get_call_depth(self) -> int:
        """Get the current function call depth."""
        return self._call_depth
    
    def set_call_depth(self, depth: int) -> None:
        """
        Set the function call depth directly.
        
        Args:
            depth: New call depth (will be clamped to valid range)
        """
        if depth < 0:
            self._call_depth = 0
        elif depth > self.max_private_depth:
            self._call_depth = self.max_private_depth
        else:
            self._call_depth = depth
    
    def __contains__(self, key: str) -> bool:
        """Check if a key is in the data store."""
        return key in self._data
    
    def items(self):
        """Return an iterator over (key, value) pairs in the data store."""
        return self._data.items()
    
    def keys(self):
        """Return an iterator over keys in the data store."""
        return self._data.keys()
    
    def values(self):
        """Return an iterator over values in the data store."""
        return self._data.values()
