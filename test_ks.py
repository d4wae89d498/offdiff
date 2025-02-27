import capstone
import keystone

# Dummy assembly code for test
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
encoding, _ = ks.asm(b"add eax, 5")
hex_bytes = bytes(encoding).hex()
byte_sequence = bytes.fromhex(hex_bytes)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

x86 = capstone.x86

# Possible pattern matching are :
pattern = [

    [0x5588, 0x9987],   # Byte seq as int array, may contains FixedPlaceholder and EnumPlaceholder -- Placeholder shall not be first iten of seq
    
    b'\x54\x48',        # Byte seq
    
    "mov",              # Dict for description
    {
        'mnemonic': 'mov', 
        'operands': [
            {'type': x86.X86_OP_REG, 'value': 'eax'},
            {'type': x86.X86_OP_MEM, 'value': 5},
        ]
    },
        
    lambda x:           #  Lambda for conditional matching => SHALL not be first items of seq
        x.mnemonic == 'mov' 
        and x.operands[0].type == capstone.x86.X86_OP_REG        
        and x.operands[1].value == 'eax'
        and x.operands[1].type == capstone.x86.X86_OP_MEM
        and (x.operands[1].value == '5' or x.operands[1].value == '6')
]

def serialize_insn(insn):
    serialized = {
        'address': insn.address,
        'mnemonic': insn.mnemonic,
        'op_str': insn.op_str,
        'bytes': insn.bytes.hex(),
        'size': insn.size,
        'operands': []
    }
    
    for operand in insn.operands:
        operand_data = {'type': operand.type}
        if operand.type == capstone.x86.X86_OP_REG:
            operand_data['value'] = md.reg_name(operand.reg)
        elif operand.type == capstone.x86.X86_OP_IMM:
            operand_data['value'] = operand.imm
        elif operand.type == capstone.x86.X86_OP_MEM:
            operand_data['value'] = {
                'base': md.reg_name(operand.mem.base) if operand.mem.base != capstone.x86.X86_REG_INVALID else None,
                'displacement': operand.mem.disp
            }
        else:
            operand_data['value'] = None
        
        serialized['operands'].append(operand_data)
    
    return serialized

# Somehow match it here
for insn in md.disasm(byte_sequence, 0x0):
    print(insn)
    print(serialize_insn(insn))
    
    for op in insn.operands:
            print(op)
            pass
    
 