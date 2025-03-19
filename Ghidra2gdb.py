def ghidra_to_gdb(ghidra_base, gdb_base, ghidra_addr):
    """Convert a Ghidra address to a GDB runtime address."""
    offset = ghidra_addr - ghidra_base
    gdb_addr = gdb_base + offset
    return hex(gdb_addr)

ghidra_base = int(input("Enter Ghidra base address (hex): "), 16) 
gdb_base = int(input("Enter GDB base address (hex): "), 16)
ghidra_addr = int(input("Enter Ghidra target address (hex): "), 16)

gdb_real_addr = ghidra_to_gdb(ghidra_base, gdb_base, ghidra_addr)
print(f"GDB runtime address: {gdb_real_addr}")
