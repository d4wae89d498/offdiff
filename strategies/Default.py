from offdiff import *

MIN_SEQ_SIZE = 4
MIN_BIAS = -16

class DefaultStrategy(AddressMatchingAbstractStrategy):


    def get_new_address_candidates(self, old_va, old_binary, new_binary, pattern = None):
        print("--", self.default_bias)
        byte_sequence = extract_bytes(old_binary, old_va, self.default_seq_size, self.default_bias)
        if not byte_sequence:
            print(f"Failed to extract bytes for VA 0x{old_va:X} in old binary.")
            print(f"old_va={old_va} size={self.default_seq_size} bias={self.default_bias}")
            return []
        old_matches = find_bytes(old_binary, byte_sequence, self.default_bias, pattern)
        if len(old_matches) > 1:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Warning: Multiple matches ({len(old_matches)}) in old binary for VA 0x{old_va:X}... Skipping it:")
            print(f"         Hex dump: {hex_pattern}")
            return []
        new_matches = find_bytes(new_binary, byte_sequence, self.default_bias, pattern)
        new_matches_len = len(new_matches)
        if new_matches_len > 1:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Warning: Multiple candidates ({new_matches_len}) in new binary for VA 0x{old_va:X}:")
            print(f"         Hex dump: {hex_pattern}")
        if new_matches_len == 0:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Pattern not found in new binary for VA 0x{old_va:X}:")
            print(f"         Hex dump: {hex_pattern}")
        if new_matches_len == 1:
            print("OK")
        return new_matches