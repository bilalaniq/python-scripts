# pattern_create.py
import sys

def create_pattern(length):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pattern = ""
    for a in charset:
        for b in charset:
            for c in charset:
                if len(pattern) >= length:
                    print(pattern[:length])
                    return
                pattern += a + b + c

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pattern_create.py <length>")
        sys.exit(1)

    try:
        length = int(sys.argv[1])
        create_pattern(length)
    except ValueError:
        print("Invalid length")
