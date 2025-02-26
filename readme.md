# offdiff

`offdiff` is a Python tool that takes old virtual addresses (VAs), as seen in debuggers like OllyDbg and CheatEngine, from a previous build of a closed-source executable and returns the new addresses from an updated build, useful for tracking changes and reverse engineering.

### Explanation of Addresses
- **Virtual Address (VA):** The address in memory where a program or library resides when it's loaded. This is what debuggers like OllyDbg and CheatEngine show.
- **Relative Virtual Address (RVA):** A virtual address adjusted relative to the base address of the module in memory.

---

### Usage (Command Line)
```bash
python main.py <old_addresses> <old_binary> <new_binary>
```

Where:
- `<old_addresses>`: A space-separated list of virtual addresses (in hexadecimal) from the old binary.
- `<old_binary>`: The path to the old binary executable.
- `<new_binary>`: The path to the new binary executable.

---

### Usage (Python)
```python
import offdiff

# Example usage
old_addresses = [0x12345678, 0x87654321]
old_binary = 'path/to/old_binary.exe'
new_binary = 'path/to/new_binary.exe'

output = offdiff.get_new_addresses(old_addresses, old_binary, new_binary)
print(output)
```

---

## Run tests of this repo:
```bash
python tests/all.py
```


### Currently supported executables
- **PE Format (Windows Executables):** `offdiff` supports Portable Executable (PE) files such as `.exe` and `.dll` on Windows platforms.
- **Unpacked Executables:** `offdiff` works with unpacked executables that do not require additional unpacking or emulation for analysis.
---

## Future Enhancements:
  - see todo file
  - see todo file
