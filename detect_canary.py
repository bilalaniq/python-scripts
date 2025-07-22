
# this script just takes in an stack dump and make an pridiction which is the canary 
# note that donot relay on this script, it is just a make pridiction which value is ends at 0x00
# you should always verify the canary by other means


import re

# Paste your stack dump here:
pxw_dump = """
0x7fffffffe6d0:  0x00007fffffffe6f8  0x0000000000000001  0x00007ffff7e0d830  0x00005555555551a0
0x7fffffffe6e0:  0x0000000000000000  0x00007fffffffe8b3  0x0000000000000002  0x2433322524333125
0x7fffffffe6f0:  0x00007ffff7fcb2c0  0x0000000000000000  0x0000000000000014  0x0000000000000000
0x7fffffffe700:  0x00007ffff7e2b560  0x00007ffff7e2b000  0x0000000000000000  0x0000000000000000
0x7fffffffe710:  0x0000000000000000  0x00007ffff7fcb2c0  0x0000000000000000  0x9f824500a4b36700
0x7fffffffe720:  0x0000000000000000  0x00007ffff7e0a3d0  0x00007fffffffe738  0x000055555555529e
0x7fffffffe730:  0x0000000000000000  0x0000000000000000  0x00007fffffffe8e0  0x000055555555529e
0x7fffffffe740:  0x0000000000000000  0x0000000000000000  0x00007fffffffe8f8  0x00007fffffffe910
"""

def detect_arch(values):
    # Detect if values are 32-bit or 64-bit based on value size
    return 64 if any(v > 0xFFFFFFFF for v in values) else 32

def is_probably_canary(val, arch):
    if val == 0x0:
        return False
    if val & 0xff != 0x00:  # must end in 0x00
        return False
    if arch == 32:
        if (val >> 24) in (0xf7, 0xff):  # libc or stack
            return False
    else:  # 64-bit
        if (val >> 56) in (0xf7, 0xff):  # high bits libc/stack
            return False
    return True

def extract_values(dump):
    values = []
    for line in dump.strip().splitlines():
        parts = re.findall(r'0x[0-9a-fA-F]+', line)
        for val in parts[1:]:  # skip address
            try:
                values.append(int(val, 16))
            except ValueError:
                pass
    return values

values = extract_values(pxw_dump)
arch = detect_arch(values)

print(f"🧠 Detected architecture: {arch}-bit")
print("🛡️  Probable stack canaries:\n")

found = False
for i, val in enumerate(values):
    if is_probably_canary(val, arch):
        print(f"🟩  Value: 0x{val:0{16 if arch == 64 else 8}x}  — Offset: %{i + 1}$p")
        found = True

if not found:
    print("❌ No likely canaries found.")

print("\nℹ️ Use %%{{offset}}$p in a format string to leak.")
