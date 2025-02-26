import lief

DEFAULT_BIAIS = 0
DEFAULT_SEQ_SIZE = 16

def extract_bytes(binary_path, va, size = DEFAULT_SEQ_SIZE, biais = DEFAULT_BIAIS):
    """Extract bytes from a virtual address (VA) with a bias."""
    binary = lief.parse(binary_path)
    if not binary:
        print("Failed to load binary.")
        return None
    
    image_base = binary.optional_header.imagebase
    rva = va - image_base
    
    section = None
    for sec in binary.sections:
        if sec.virtual_address <= rva < sec.virtual_address + sec.size:
            section = sec
            break
    
    if not section:
        print(f"No section found for VA 0x{va:X} (RVA 0x{rva:X}).")
        return None
    
    raw_offset = rva - section.virtual_address
    adjusted_offset = raw_offset + biais
    if adjusted_offset < 0 or adjusted_offset + size > len(section.content):
        print(f"Address out of range in section '{section.name}'.")
        return None
    
    return bytes(section.content[adjusted_offset : adjusted_offset + size])

def find_bytes(binary_path, byte_sequence, biais = DEFAULT_BIAIS):
    """Find all virtual addresses (VA) where the byte sequence occurs."""
    binary = lief.parse(binary_path)
    if not binary:
        print("Failed to load binary.")
        return []
    
    image_base = binary.optional_header.imagebase
    matches = []
    
    for sec in binary.sections:
        sec_va_start = image_base + sec.virtual_address
        sec_va_end = sec_va_start + sec.size
        
        content = bytes(sec.content)
        index = content.find(byte_sequence)
        while index != -1:
            va = sec_va_start + index
            matches.append(va)
            index = content.find(byte_sequence, index + 1)
    
    return matches

def hex_dump(byte_sequence):
    """Format a byte sequence into a hex dump."""
    return " ".join(f"{byte:02X}" for byte in byte_sequence)

def get_new_addresses(old_addresses, old_binary, new_binary):
    """Find new addresses corresponding to old addresses with bias adjustment."""
    new_addresses = []
    for item in old_addresses:
        
        old_va = item[0]
        size = DEFAULT_SEQ_SIZE
        biais = DEFAULT_BIAIS
        
        item_len = len(item)
        if item_len >= 2:
                size = int(item[1])
        if item_len == 3:
                biais = int(item[2])
        else:
                raise "Argument error"
            
        byte_sequence = extract_bytes(old_binary, old_va, size, biais)
        if not byte_sequence:
            print(f"Failed to extract bytes for VA 0x{old_va:X} in old binary.")
            print(f"old_va={old_va} size={size} biais={biais}")
            continue
        
        old_matches = find_bytes(old_binary, byte_sequence)
        if len(old_matches) > 1:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Error: Multiple matches ({len(old_matches)}) in old binary for VA 0x{old_va:X}:")
            print(f"         Hex dump: {hex_pattern}")
            raise "error"
        
        new_matches = find_bytes(new_binary, byte_sequence)
        new_matches_len = len(new_matches)
        if new_matches_len > 1:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Warning: Multiple candidates ({new_matches_len}) in new binary for VA 0x{old_va:X}:")
            print(f"         Hex dump: {hex_pattern}")
        if new_matches_len == 0:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Pattern not found in new binary for VA 0x{old_va:X}:")
            print(f"Hex dump: {hex_pattern}")
        
        adjusted_matches = [va - biais for va in new_matches]
        new_addresses.append(adjusted_matches)
    
    return new_addresses

def print_addresses(address_groups, num_format='hex', addresses_per_line=8):
    if not address_groups:
        print("No addresses to print.")
        return

    # Validate the number format and define formatting details.
    format_map = {
        'hex': ('x', 'hexadecimal'),
        'octal': ('o', 'octal'),
        'decimal': ('d', 'decimal')
    }
    if num_format not in format_map:
        raise ValueError(f"Invalid format: {num_format}. Use 'hex', 'octal', or 'decimal'")
    
    fmt, fmt_name = format_map[num_format]

    # Begin printing the outer list.
    print("[")
    for group in address_groups:
        # Handle empty sublists.
        if not group:
            print("    [],")
            continue

        # Determine maximum numeric length for padding in this group.
        max_len = 8 if num_format == 'hex' else max(len(format(addr, fmt)) for addr in group)

        # Create formatted addresses for the current group.
        formatted = []
        for addr in group:
            numeric = format(addr, fmt).rjust(max_len, '0')
            # The prefix remains hard-coded as 0x with ANSI color codes.
            colored_addr = f"\033[94m0x\033[92m{numeric}\033[0m"
            formatted.append(colored_addr)

        # Print the group's addresses either on one line or spread over multiple lines.
        if len(group) <= addresses_per_line:
            print("    " + "[" + ", ".join(formatted) + "],")
        else:
            print("    [")
            for i in range(0, len(formatted), addresses_per_line):
                line = formatted[i:i + addresses_per_line]
                print("        " + ", ".join(line))
            print("    ],")
    print("]")
