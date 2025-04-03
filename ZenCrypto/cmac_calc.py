import argparse
import sys
from aes_cmac import aes_cmac

def main():
    parser = argparse.ArgumentParser(description="Calculate AES-128 CMAC of a segment of a binary file.")
    # NIST SP 800-38B example key 2b7e151628aed2a6abf7158809cf4f3c
    parser.add_argument("key", help="AES key in hexadecimal (32 hex digits for AES-128)")
    parser.add_argument("binary_file", help="Path to the binary file")
    # 0x120
    parser.add_argument("offset", type=lambda x: int(x,0), help="Byte offset in the file")
    # 0x100
    parser.add_argument("length", type=lambda x: int(x,0), help="Number of bytes to read (must be a multiple of 16)")
    args = parser.parse_args()

    try:
        key_bytes = bytes.fromhex(args.key)
    except ValueError:
        print("Error: Key must be a valid hexadecimal string.")
        sys.exit(1)
    
    if len(key_bytes) != 16:
        print("Error: Key must be 16 bytes (32 hex characters) for AES-128.")
        sys.exit(1)
    
    if args.length % 16 != 0:
        print("Error: Length must be a multiple of 16 bytes.")
        sys.exit(1)

    try:
        with open(args.binary_file, "rb") as f:
            f.seek(args.offset)
            data = f.read(args.length)
            if len(data) != args.length:
                print("Error: Could not read the required number of bytes from file.")
                sys.exit(1)
    except IOError as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    try:
        cmac = aes_cmac(key_bytes, data)
        print("CMAC (hex):", cmac.hex())
    except Exception as e:
        print(f"Error calculating CMAC: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
