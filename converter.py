def to_printable_bytes(data: bytes) -> str:
    return ' '.join(f"{b:02x}" for b in data)

def show_menu():
    print("\nSelect input type:")
    print("1. string")
    print("2. hex")
    print("3. int")
    print("4. bin")
    print("5. bytes")

    choice = input("Enter option number (1–5): ").strip()
    return choice

def handle_conversion():
    choice = show_menu()
    raw = input("Enter the value: ").strip()

    if choice == "1":  # string
        data = raw.encode()
    elif choice == "2":  # hex
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            print("❌ Invalid hex input.")
            return
    elif choice == "3":  # int
        try:
            num = int(raw)
            data = num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big')
        except ValueError:
            print("❌ Invalid integer input.")
            return
    elif choice == "4":  # bin
        try:
            num = int(raw, 2)
            data = num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big')
        except ValueError:
            print("❌ Invalid binary input.")
            return
    elif choice == "5":  # bytes
        try:
            data = eval(raw)
            if not isinstance(data, bytes):
                raise ValueError
        except:
            print("❌ Invalid bytes input. Example: b'\\x41\\x42'")
            return
    else:
        print("❌ Invalid option.")
        return

    print("\n======[ 🔍 Converted Output ]======")
    try:
        print(f"ASCII     : {data.decode('utf-8')}")
    except UnicodeDecodeError:
        print("ASCII     : [Non-printable or binary data]")
    print(f"Hex       : {data.hex()}")
    print(f"Binary    : {' '.join(bin(b)[2:].zfill(8) for b in data)}")
    print(f"Decimal   : {' '.join(str(b) for b in data)}")
    print(f"Bytes     : {data}")
    print(f"Int (big endian)   : {int.from_bytes(data, 'big')}")
    print(f"Int (little endian): {int.from_bytes(data, 'little')}")
    print("===================================")

def from_input():
    while True:
        handle_conversion()
        again = input("\nDo you want to convert another input? (y/n): ").strip().lower()
        if again != 'y':
            print("Bye 👋")
            break

if __name__ == "__main__":
    from_input()
