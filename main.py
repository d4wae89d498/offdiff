import sys
from offdiff import * 

def main():
    # Extract command-line arguments excluding the script name
    args = sys.argv[1:]
    
    # Define usage message
    usage = """
Usage: script.py [old_address1] [old_address2] ... [old_binary] [new_binary]
- Minimum of 3 arguments required.
- Use 'help' to display this message.
"""
    
    # Check for help command
    if "help" in args or "-h" in args or "--help" in args:
        print(usage)
        return
    
    # Check if the number of arguments is less than 3
    if len(args) < 3:
        print("Error: Insufficient arguments provided.")
        print(usage)
        return
    
    # Process the arguments
    old_addresses_text = args[:-2]  # All arguments except the last two
    old_binary = args[-2]      # Second-to-last argument
    new_binary = args[-1]      # Last argument
    
    old_addresses = []
    for addr in old_addresses_text:
        
        items = addr.split(':')
        items_len = len(items)

        if (items_len <= 0):
            raise InvalidArgumentException("Usage error.")

        arguments = [int(items[0], 16), DEFAULT_SEQ_SIZE, DEFAULT_BIAS]
        if items_len >= 2:
            arguments[1] = int(items[1])
        if items_len == 3:
            arguments[2] = int(items[2])
        else:
            raise InvalidArgumentException("Usage error.")
        
        old_addresses.append(arguments)
        
    print("Old Addresses:", old_addresses)
    print("Old Binary:", old_binary)
    print("New Binary:", new_binary)
    print("-----------")
    
    output = get_new_addresses(old_addresses, old_binary, new_binary)
    
    print_addresses(output)

if __name__ == "__main__":
    main()
