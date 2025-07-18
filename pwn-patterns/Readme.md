
# Pattern Generator & Offset Finder

This directory contains two Python scripts inspired by Metasploit's `pattern_create.rb` and `pattern_offset.rb`. These tools help you discover the exact offset needed for buffer overflow exploitation.

## 🔧 Scripts

### `pattern_create.py`
Generates a unique, non-repeating pattern of a specified length.

**Usage:**
```bash
python3 pattern_create.py <length>
```

**Example:**
```bash
python3 pattern_create.py 100
```

---

### `pattern_offset.py`
Finds the exact offset of a value within a pattern.

**Usage:**
```bash
python3 pattern_offset.py <value> <pattern_length>
```
- `<value>`: The overwritten value (e.g., from EIP, RIP, or register dump).
- `<pattern_length>`: The length of the original pattern.

**Example:**
```bash
python3 pattern_offset.py AAYAAZAB 300
```

---

## 💡 Tip

Use these scripts during exploit development to determine how many bytes are needed to overwrite a return address, function pointer, or other control structure.


