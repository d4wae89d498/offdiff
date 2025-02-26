import os
import sys

script_path = os.path.abspath(__file__)
script_root = os.path.dirname(script_path)
project_root = os.path.realpath(script_root + "/../../")

print(project_root)
sys.path.insert(0, project_root)

from offdiff import get_new_addresses, print_addresses

new_binary = "game-4mb.exe"
old_binary = "game-34mb.exe"
old_addresses = [
        (0x0040E00D, 16, 4) # becomes 0x0040e0bd (addresse used to sometime encrypt/xor sah filecount)  
]

output = get_new_addresses(old_addresses, os.path.join(script_root, old_binary), os.path.join(script_root, new_binary))

# test print_addresses with muliple outputs:
#test = []
#for i in range (15):
#        test.append(0x41)
#output.append(test)
#for i in range (15):
#        output.append([0x42])

assert(output[0][0] == 0x0040e0bd)

print_addresses(output)
