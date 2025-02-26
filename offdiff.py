import lief

DEFAULT_BIAS = 0
DEFAULT_SEQ_SIZE = 16
MIN_SEQ_SIZE = 4
MIN_BIAS = -16

class UserException(Exception):
    pass

class InvalidArgumentException(UserException):
    pass
class InvalidAddressException(UserException):
    pass
class InvalidFileException(UserException):
    pass

class BytePlaceholder():
    def __init__(self, i):
                self.size = i
def bskip(i):
    """Simply return the length of the placeholder used for pattern matching"""
    return BytePlaceholder(i)

def pattern_size(pattern):
    """Calculate the size of the byte-pattern, including its placeholder. Takes a list of either int or placeholder."""
    total_size = 0
    for item in pattern:
        if isinstance(item, BytePlaceholder):
            total_size += item.size
        else:
            total_size += (item.bit_length() + 7) // 8  # This computes the number of bytes needed for the number
    
    return total_size

def pattern_match(pattern, byte_sequence):
    expected_size = pattern_size(pattern)
    if len(byte_sequence) != expected_size:
        return False
    pos = 0
    for item in pattern:
        if isinstance(item, BytePlaceholder):
            pos += item.size
            if pos > len(byte_sequence):
                return False
        else:
            bits = item.bit_length()
            bytes_needed = (bits + 7) // 8
            if bytes_needed == 0 and item == 0:
                bytes_needed = 1  # Handle 0 as 1 byte
            if pos + bytes_needed > len(byte_sequence):
                return False
            try:
                expected_bytes = item.to_bytes(bytes_needed, byteorder='big')
            except OverflowError:
                return False
            current_bytes = byte_sequence[pos:pos + bytes_needed]
            if current_bytes != expected_bytes:
                return False
            pos += bytes_needed
    return pos == len(byte_sequence)

def extract_bytes(binary, va, size = DEFAULT_SEQ_SIZE, bias = DEFAULT_BIAS):
    """Extract bytes from a virtual address (VA) with a bias."""
    image_base = binary.optional_header.imagebase
    rva = va - image_base
    section = None
    for sec in binary.sections:
        if sec.virtual_address <= rva < sec.virtual_address + sec.size:
            section = sec
            break
    if not section:
        raise InvalidAddressException(f"No section found for VA 0x{va:X} (RVA 0x{rva:X}).")
    raw_offset = rva - section.virtual_address
    adjusted_offset = raw_offset + bias
    if adjusted_offset < 0 or adjusted_offset + size > len(section.content):
        raise InvalidAddressException(f"Address out of range in section '{section.name}'.")
    return bytes(section.content[adjusted_offset : adjusted_offset + size])

class BytePlaceholder:
    def __init__(self, i):
        self.size = i

def bskip(i):
    return BytePlaceholder(i)

def pattern_size(pattern):
    total_size = 0
    for item in pattern:
        if isinstance(item, BytePlaceholder):
            total_size += item.size
        else:
            total_size += (item.bit_length() + 7) // 8
    return total_size

def pattern_match(pattern, byte_sequence):
    expected_size = pattern_size(pattern)
    if len(byte_sequence) != expected_size:
        return False
    pos = 0
    for item in pattern:
        if isinstance(item, BytePlaceholder):
            pos += item.size
            if pos > len(byte_sequence):
                return False
        else:
            bits = item.bit_length()
            bytes_needed = (bits + 7) // 8
            if bytes_needed == 0 and item == 0:
                bytes_needed = 1  # Handle 0 as 1 byte
            if pos + bytes_needed > len(byte_sequence):
                return False
            try:
                expected_bytes = list(item.to_bytes(bytes_needed, byteorder='big'))
            except OverflowError:
                return False
            current_bytes = list(byte_sequence[pos:pos + bytes_needed])
            if current_bytes != expected_bytes:
                return False
            pos += bytes_needed
    return pos == len(byte_sequence)

class InvalidParameterException(Exception):
    pass

DEFAULT_BIAS = 0

def find_bytes(binary, byte_sequence, bias=DEFAULT_BIAS, pattern=None):
    """Find all virtual addresses (VA) where the byte sequence or pattern occurs."""
    if pattern and not pattern_match(pattern, byte_sequence):
        raise InvalidParameterException("byte sequence doesn't match pattern")
    if pattern:
        print("ITS A MATCH")
    image_base = binary.optional_header.imagebase
    matches = []
    
    expected_size = pattern_size(pattern) if pattern else len(byte_sequence)
    
    for sec in binary.sections:
        sec_va_start = image_base + sec.virtual_address
        content = bytes(sec.content)
        sec_length = len(content)
        
        if sec_length < expected_size:
            continue
        
        if pattern:
            # Search for pattern matches
            for index in range(sec_length - expected_size + 1):
                current_chunk = content[index:index + expected_size]
                if pattern_match(pattern, current_chunk):
                    va = sec_va_start + index - bias
                    matches.append(va)
                    if len(matches) > 10:
                        break
        else:
            # Search for the byte_sequence
            index = content.find(byte_sequence)
            while index != -1:
                va = sec_va_start + index - bias
                matches.append(va)
                index = content.find(byte_sequence, index + 1)
                if len(matches) > 10:
                    break
    return matches

def hex_dump(byte_sequence):
    """Format a byte sequence into a hex dump."""
    return " ".join(f"{byte:02X}" for byte in byte_sequence)


class AddressMatchingAbstractStrategy():
        def __init__(
            self, 
            min_seq_size=MIN_SEQ_SIZE, 
            min_bias=MIN_BIAS, 
            default_seq_size=DEFAULT_SEQ_SIZE, 
            default_bias=DEFAULT_BIAS
        ):
                self.min_seq_size = min_seq_size
                self.min_bias = min_bias
                self.default_seq_size = default_seq_size
                self.default_bias = default_bias
        
        def get_new_address_candidates(self, old_va, old_binary, new_binary, pattern = None):
                raise NotImplementedError("This method should be overridden by subclasses.")

from strategies import DefaultStrategy

class AddressCandidate:
        def __init__(
            self, 
            origin, 
            candidates,
        ):
                self.origin = origin
                self.candidates = candidates
                self.pattern = None
        def __str__(self):
                return f"{self.candidates}"
        
        def __repr__(self):
                return self.__str__()        

def get_new_addresses(old_addresses, old_binary_path, new_binary_path, strategy = DefaultStrategy()):
    """Find new addresses corresponding to old addresses with bias adjustment."""
    old_binary = lief.parse(old_binary_path)
    if not old_binary:
        InvalidFileException(f"Failed to load binary {old_binary}")
        return None
    new_binary = lief.parse(new_binary_path)
    if not new_binary:
        InvalidFileException(f"Failed to load binary {new_binary_path}")
        return None

    new_addresses = dict()
    for item in old_addresses:
        item_len = len(item)
        if item_len <= 1 or item_len > 4:
                raise InvalidArgumentException("Argument error")   
        old_va = item[1]
        size = DEFAULT_SEQ_SIZE
        bias = DEFAULT_BIAS
        pattern = None
        if item_len >= 3 and isinstance(item[2], int):
                size = int(item[2])
        elif item_len >= 3 and isinstance(item[2], list):
                pattern = item[2]
                size = pattern_size(pattern)                
        if item_len == 4:
                bias = int(item[3])
        strategy.default_seq_size = size
        strategy.default_bias = bias
        strategy.pattern = pattern
        new_addresses[item[0]] = AddressCandidate(old_va, strategy.get_new_address_candidates(old_va, old_binary, new_binary, pattern))
    return new_addresses

def print_addresses(address_groups, num_format='hex', addresses_per_line=8):
    """Pretty print offdiff results"""
    if not address_groups:
        InvalidArgumentException("No addresses to print.")
        return
    format_map = {
        'hex': ('x', 'hexadecimal'),
        'octal': ('o', 'octal'),
        'decimal': ('d', 'decimal')
    }
    if num_format not in format_map:
        raise InvalidArgumentException(f"Invalid format: {num_format}. Use 'hex', 'octal', or 'decimal'")
    fmt, fmt_name = format_map[num_format]
    print("[")
    for name, value in address_groups.items():
        print(f"{name:<18}", end='')
        if not value.candidates:
            print("    [],")
            continue
        max_len = 8 if num_format == 'hex' else max(len(format(addr, fmt)) for addr in group)
        formatted = []
        for addr in value.candidates:
            numeric = format(addr, fmt).rjust(max_len, '0')
            colored_addr = f"\033[94m0x\033[92m{numeric}\033[0m"
            formatted.append(colored_addr)
        if len(value.candidates) <= addresses_per_line:
            print("    " + "[" + ", ".join(formatted) + "],")
        else:
            print("    [")
            for i in range(0, len(formatted), addresses_per_line):
                line = formatted[i:i + addresses_per_line]
                print("        " + ", ".join(line))
            print("    ],")
    print("]")
