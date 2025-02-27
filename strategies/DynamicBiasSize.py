from offdiff import *

class DynamicBiasSizeStrategy(AddressMatchingAbstractStrategy):

    def get_new_address_candidates(self, old_address, old_binary, new_binary, pattern = None):
        size = self.default_seq_size
        
        while size >= self.min_seq_size:
                byte_sequence = extract_bytes(old_binary, old_address, size, bias)
                if not byte_sequence:
                        size -= 1
                continue

        new_matches = find_bytes(new_binary, byte_sequence)
        if new_matches:
                adjusted_matches = [va - bias for va in new_matches]
                return adjusted_matches

        if bias > self.min_bias:
                bias -= 1
        else:
                size -= 1
                bias = self.DEFAULT_BIAS 

        return []