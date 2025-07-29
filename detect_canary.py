
# this script just takes in an stack dump and make an pridiction which is the canary 
# note that donot relay on this script, it is just a make pridiction which value is ends at 0x00
# you should always verify the canary by other means


import re

# Paste your stack dump here:
pxw_dump = """
0x7fffffffde90  0x4143414142414141  0x4641414541414441   AAABAACAADAAEAAF
0x7fffffffdea0  0x4141484141474141  0x414b41414a414149   AAGAAHAAIAAJAAKA
0x7fffffffdeb0  0x4e41414d41414c41  0x41415041414f4141   ALAAMAANAAOAAPAA
0x7fffffffdec0  0x4153414152414151  0x5641415541415441   QAARAASAATAAUAAV
0x7fffffffded0  0x4141584141574141  0x416141415a414159   AAWAAXAAYAAZAAaA
0x7fffffffdee0  0x6441416341416241  0x4141664141654141   AbAAcAAdAAeAAfAA
0x7fffffffdef0  0x0000000068414167  0x00007ffff7ddfca8   gAAh............
0x7fffffffdf00  0x00007fffffffdff0  0x00000000004011d7   ..........@.....
0x7fffffffdf10  0x0000000100400040  0x00007fffffffe008   @.@.............
0x7fffffffdf20  0x00007fffffffe008  0x522e396ce89e63b8   .........c..l9.R
0x7fffffffdf30  0x0000000000000000  0x00007fffffffe018   ................
0x7fffffffdf40  0x00007ffff7ffd000  0x0000000000000000   ................
0x7fffffffdf50  0xadd1c693569c63b8  0xadd1d6d7105c63b8   .c.V.....c\.....
0x7fffffffdf60  0x0000000000000000  0x0000000000000000   ................
0x7fffffffdf70  0x0000000000000000  0x0000000000000000   ................
0x7fffffffdf80  0x00007fffffffe018  0xeff4eeae330cb400   ...........3....
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
