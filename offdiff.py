import lief

def extract_bytes(binary_path, va, size):
    """Extract bytes from a virtual address (VA) as seen in debuggers."""
    binary = lief.parse(binary_path)
    if not binary:
        print("Failed to load binary.")
        return None
    
    # Get image base (base address in memory)
    image_base = binary.optional_header.imagebase
    
    # Convert VA to RVA (Relative Virtual Address)
    rva = va - image_base
    
    # Find the section containing the RVA
    section = None
    for sec in binary.sections:
        if sec.virtual_address <= rva < sec.virtual_address + sec.size:
            section = sec
            break
    
    if not section:
        print(f"No section found for VA 0x{va:X} (RVA 0x{rva:X}).")
        return None
    
    # Calculate the raw file offset within the section
    raw_offset = rva - section.virtual_address
    if raw_offset < 0 or raw_offset + size > len(section.content):
        print(f"Address out of range in section '{section.name}'.")
        return None
    
    return bytes(section.content[raw_offset : raw_offset + size])

def find_bytes(binary_path, byte_sequence):
    """Find all virtual addresses (VA) where the byte sequence occurs in the file."""
    binary = lief.parse(binary_path)
    if not binary:
        print("Failed to load binary.")
        return None
    
    image_base = binary.optional_header.imagebase
    matches = []
    
    for sec in binary.sections:
        # Calculate VA range for the section
        sec_va_start = image_base + sec.virtual_address
        sec_va_end = sec_va_start + sec.size
        
        # Search for the byte sequence in the section's raw content
        content = bytes(sec.content)
        index = content.find(byte_sequence)
        while index != -1:
            # Convert raw index to VA
            va = sec_va_start + index
            matches.append(va)
            index = content.find(byte_sequence, index + 1)
    
    return matches

def hex_dump(byte_sequence):
    """Format a byte sequence into a hex dump."""
    return " ".join(f"{byte:02X}" for byte in byte_sequence)

def get_new_addresses(old_addresses, old_binary, new_binary, size=32):
    new_addresses = []
    for old_va in old_addresses:
            
        # todo: check if old_contains a size and/or and offset
            
        # Extract bytes from the old binary using the VA
        byte_sequence = extract_bytes(old_binary, old_va, size)
        if not byte_sequence:
            print(f"Failed to extract bytes for VA 0x{old_va:X} in old binary.")
            continue
        
        # Check for multiple matches in the old binary (for debugging)
        old_matches = find_bytes(old_binary, byte_sequence)
        if len(old_matches) > 1:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Warning: Multiple matches ({len(old_matches)}) in old binary for VA 0x{old_va:X}:")
            print(f"         Hex dump: {hex_pattern}")
        
        # Search for the byte sequence in the new binary
        new_matches = find_bytes(new_binary, byte_sequence)
        if len(new_matches) == 1:
            new_addresses.append(new_matches[0])
        elif len(new_matches) > 1:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Error: Multiple matches in new binary for VA 0x{old_va:X}:")
            print(f"       Hex dump: {hex_pattern}")
        else:
            hex_pattern = hex_dump(byte_sequence)
            print(f"Pattern not found in new binary for VA 0x{old_va:X}:")
            print(f"Hex dump: {hex_pattern}")
    
    return new_addresses


def print_addresses(addresses, num_format='hex', addresses_per_line=8):
    if not addresses:
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

    # Determine maximum numeric length for padding
    max_len = 8 if num_format == 'hex' else max(len(format(addr, fmt)) for addr in addresses)

    # Create the formatted addresses with ANSI color codes.
    formatted = []
    for addr in addresses:
        numeric = format(addr, fmt).rjust(max_len, '0')
        # Here the prefix is hard-coded as 0x (colored) even if using a different number base.
        colored_addr = f"[\033[94m0x\033[92m{numeric}\033[0m]"
        formatted.append(colored_addr)

    # If the total addresses fit on one line, print them in one bracketed line.
    if len(addresses) <= addresses_per_line:
        print("[" + ", ".join(formatted) + "]")
    else:
        # Otherwise, print multi-line: opening bracket, indented lines of addresses, and closing bracket.
        print("[")
        for i in range(0, len(formatted), addresses_per_line):
            line = formatted[i:i + addresses_per_line]
            print("    " + ", ".join(line))
        print("]")
