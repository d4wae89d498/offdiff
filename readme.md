# offdiff
`offdiff` is a Python tool that takes old virtual addresses (VAs) from a previous build of a closed-source executable and returns the new addresses from an updated build, useful for tracking changes and reverse engineering.

---

### Key Features
- **Address Translation:** Map old virtual addresses to new ones across different binary versions
- **Bias Support:** Shift byte sequence extraction to avoid unstable regions (e.g., external code addresses)
- **Size Specification:** Define exact byte sequence lengths for precise pattern matching

---

### Core Concepts
| Term | Description |
|------|-------------|
| **VA (Virtual Address)** | Memory address as seen in debuggers like CheatEngine or OllyDbg |
| **RVA (Relative VA)** | Address relative to the module's base address |
| **Bias** | Byte offset applied to shift pattern extraction (±N bytes) |
| **Size** | Length of the byte sequence to extract/match |

---

### Usage (Command Line)
```bash
$ python main.py <address_spec 1> <address_spec 2> ... <address_spec n> <old_binary> <new_binary>
```
**address_spec** can be specified in the following formats:
- `addr`
- `addr:size`
- `addr:size:bias`

Where:
- `addr` is the address in hexadecimal (with or without the 0x prefix).
- `size` (optional) is the length of the byte sequence to extract/match (default: 16).
- `bias` (optional) is the byte offset applied for pattern extraction (default: 0).

**old_binary** and **new_binary** are relative paths to the old binary (which contains the old addresses as specified in address_spec) and the new binary (the one we are looking to find the corresponding addresses in).


Exemple:
```bash
$ python main.py 0x0040E00D:16:0 tests/shaiya/game-4mb.exe tests/shaiya/game-34mb.exe 

Old Addresses: [[4251661, 16, 0]]
Old Binary: tests/shaiya/game-4mb.exe
New Binary: tests/shaiya/game-34mb.exe
-----------
[
    [0x0040df5d],
]
```

### Usage (python)

```python

from offdiff import get_new_addresses, print_addresses

new_binary = "game-4mb.exe"
old_binary = "game-34mb.exe"
old_addresses = [
        ("SahEncr",         0x0040E00D, 16, 1),    # -> 0x0040e0bd
        ("InvetoryExit_01", 0x0051AAD5, 7, -2),   # -> 0x005186b5
        ("InvetoryExit_02", 0x0051A5C1, 15, -2),   # -> 0x005181a1
        ("CallNB_01",       0x0057BC50, [0xCC, 0x8B11, 0x83EC74, 0x85D2, bskip(6), 0xDB442478], -1),          # -> 0x0057b860  
        ("InvetoryExit_03", 0x00519642,),   
        ("JMPNB_NPCID_01",  0x00519667,),   
        ("JMPNB_NPCID_02",  0x0051A503,),   
        ("CallNB_02",       0x00422D40,)
]


output = get_new_addresses(old_addresses, new_binary, old_binary)
assert(output[0][0] == 0x0040e0bd)
print_addresses(output)
```
```text
[
SahEncr               [0x0040e0bd],
InvetoryExit_01       [0x005186b5],
InvetoryExit_02       [0x005181a1],
CallNB_01             [0x0057b860],
InvetoryExit_03       [0x005196e2],
JMPNB_NPCID_01        [0x00519707],
JMPNB_NPCID_02        [0x0051a5a3],
CallNB_02             [0x00423150],
]
```

### Advanced pattern matching using keystone // capstone

```python
# TODO
```

### Run tests of this repo:

```bash
python tests/all.py
```


### Currently supported executables
- **PE Format (Windows Executables):** `offdiff` supports Portable Executable (PE) files such as `.exe` and `.dll` on Windows platforms.
- **Unpacked Executables:** `offdiff` works with unpacked executables that do not require additional unpacking or emulation for analysis.

---

### Future Enhancements:
  - see todo file
  - see todo file
