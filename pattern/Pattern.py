from .AbstractPlaceholder import *

class Pattern():
    def __init__(self, pattern):
        self.pattern = pattern
        
    def size(self):
        """Calculate the size of the byte-pattern, including its placeholder. Takes a list of either int or placeholder."""
        total_size = 0
        for item in self.pattern:
            if isinstance(item, AbstractPlaceholder):
                total_size += item.size
            else:
                total_size += (item.bit_length() + 7) // 8  # This computes the number of bytes needed for the number
    
        return total_size
        
        def match():
                pass
                