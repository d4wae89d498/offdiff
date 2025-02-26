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
        0x0040ED # becomes 0x0040e0bd (addresse used to sometime encrypt/xor sah filecount)  
]
output = get_new_addresses([0x0040E00D], os.path.join(script_root, old_binary), os.path.join(script_root, new_binary), 16)

# todo: test output when mutliple addresses:
for i in range (0,0):
        output.append(0x41)

assert(output[0] == 0x0040e0bd)

print_addresses(output)
