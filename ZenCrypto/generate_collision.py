#!/usr/bin/env python3
import sys
import argparse

# Import functions from the three provided modules.
from aes_cmac_collide import generate_collision_buffer
from try_factor import factor_256
from calc_mont_inv import montgomery_inverse_gmpy2

def format_c_array(name: str, data: bytes) -> str:
    """
    Format a bytes object as a C byte array.
    Example output:
      unsigned char name[] = { 0x12, 0x34, 0xab, 0xcd, ... };
    """
    arr = ", ".join(f"0x{b:02x}" for b in data)
    return f"unsigned char {name}[] = {{ {arr} }};"

def int_to_bytes(i: int) -> bytes:
    """
    Convert an integer to its minimal big-endian bytes representation.
    """
    length = (i.bit_length() + 7) // 8 or 1
    return i.to_bytes(length)

def main():
    parser = argparse.ArgumentParser(
        description="Generate a collision buffer (N), factor it (p and q), and compute its Montgomery inverse."
    )
    parser.add_argument("--key", default="2b7e151628aed2a6abf7158809cf4f3c",
                        help="AES key in hex (default: 2b7e151628aed2a6abf7158809cf4f3c)")
    parser.add_argument("--target_cmac", default="9a3631fe88727fa8202dffa9a528730b",
                        help="Target CMAC value in hex (default: 9a3631fe88727fa8202dffa9a528730b)")
    parser.add_argument("--max_factor", type=int, default=5000,
                        help="Maximum allowed factor (default: 5000)")
    args = parser.parse_args()

    # Convert key and target CMAC from hex to bytes.
    try:
        key = bytes.fromhex(args.key)
    except ValueError:
        print("Invalid key hex string.", file=sys.stderr)
        sys.exit(1)

    try:
        target_cmac = bytes.fromhex(args.target_cmac)
    except ValueError:
        print("Invalid target CMAC hex string.", file=sys.stderr)
        sys.exit(1)

    # Generate collision buffer (N) and factor it.
    N = None
    factors = None
    max_attempts = 100
    attempt = 0

    while attempt < max_attempts:
        N = generate_collision_buffer(key, target_cmac)
        # factor_256 is assumed to take two arguments: the 256-byte buffer and max_factor.
        factors = factor_256(N, args.max_factor)
        if factors is not None:
            break
        attempt += 1

    if factors is None:
        print(f"Failed to factor the generated collision buffer within {max_attempts} attempts.", file=sys.stderr)
        sys.exit(1)

    p, q = factors

    # Compute the Montgomery inverse using gmpy2.
    mont_inv = montgomery_inverse_gmpy2(N)
    if mont_inv is None:
        print("Montgomery inverse does not exist for the generated collision buffer.", file=sys.stderr)
        sys.exit(1)

    # Output all values as hex strings and as C byte arrays.
    print("=== RESULTS ===\n")
    
    # N: collision buffer (256 bytes)
    print("N (collision buffer) as hex:")
    print(N.hex())
    print("\nN (collision buffer) as C byte array:")
    print(format_c_array("N", N))
    print("\n---------------------\n")
    
    # p and q: factors (small integers)
    p_bytes = int_to_bytes(p)
    q_bytes = int_to_bytes(q)
    print("p as hex: 0x" + hex(p)[2:])
    print("p as C byte array:")
    print(format_c_array("p", p_bytes))
    print("\n---------------------\n")
    
    print("q as hex: 0x" + hex(q)[2:])
    print("q as C byte array:")
    print(format_c_array("q", q_bytes))
    print("\n---------------------\n")
    
    # Montgomery inverse: 256-byte value.
    print("Montgomery inverse as hex:")
    print(mont_inv.hex())
    print("\nMontgomery inverse as C byte array:")
    print(format_c_array("mont_inv", mont_inv))
    print("\n=====================")

if __name__ == "__main__":
    main()
