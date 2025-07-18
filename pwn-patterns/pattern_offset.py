# pattern_offset.py
import sys

def create_pattern(length):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pattern = ""
    for a in charset:
        for b in charset:
            for c in charset:
                if len(pattern) >= length:
                    return pattern[:length]
                pattern += a + b + c
    return pattern

def find_offset(substring, length):
    pattern = create_pattern(length)
    offset = pattern.find(substring)
    if offset == -1:
        print(f"[-] Pattern not found.")
    else:
        print(f"[+] Exact match at offset: {offset}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 pattern_offset.py <substring> <length>")
        sys.exit(1)

    find_offset(sys.argv[1], int(sys.argv[2]))
