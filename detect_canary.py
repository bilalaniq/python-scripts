
# this script just takes in an stack dump and make an pridiction which is the canary 
# note that donot relay on this script, it is just a make pridiction which value is ends at 0x00
# you should always verify the canary by other means


import re

# Paste your stack dump here:
pxw_dump = """
0x7fffffffde90  0x00007025 0x000000b7 0x00000000 0x00000000  %p..............
0x7fffffffdea0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7fffffffdeb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7fffffffdec0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7fffffffded0  0x00000000 0x00000000 0x2dfe2600 0xda78b052  .........&.-R.x.
0x7fffffffdee0  0xffffdef0 0x00007fff 0x004011e5 0x00000000  ..........@.....
0x7fffffffdef0  0x00000001 0x00000000 0xf7ddfca8 0x00007fff  ................
0x7fffffffdf00  0xffffdff0 0x00007fff 0x004011d7 0x00000000  ..........@.....
0x7fffffffdf10  0x00400040 0x00000001 0xffffe008 0x00007fff  @.@.............
0x7fffffffdf20  0xffffe008 0x00007fff 0x59b258cd 0x5ed6c09e  .........X.Y...^
0x7fffffffdf30  0x00000000 0x00000000 0xffffe018 0x00007fff  ................
0x7fffffffdf40  0xf7ffd000 0x00007fff 0x00000000 0x00000000  ................
0x7fffffffdf50  0xe7b058cd 0xa1293f61 0xa17058cd 0xa1292f25  .X..a?)..Xp.%/).
0x7fffffffdf60  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7fffffffdf70  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7fffffffdf80  0xffffe018 0x00007fff 0x2dfe2600 0xda78b052  .........&.-R.x.
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

print("🛡️  Probable stack canaries:\n")

found = False
for i, val in enumerate(values):
    if is_probably_canary(val, arch):
        print(f"🟩  Value: 0x{val:0{16 if arch == 64 else 8}x}  — Offset: %{i + 1}$p")
        found = True

if not found:
    print("❌ No likely canaries found.")

print("\nℹ️ Use %%{{offset}}$p in a format string to leak.")
