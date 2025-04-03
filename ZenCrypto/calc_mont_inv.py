#!/usr/bin/env python3
import sys
import argparse
import gmpy2

def montgomery_inverse_gmpy2(data: bytes) -> bytes:
    """
    Compute the adjusted Montgomery inverse of a 256-byte buffer using gmpy2.invert.
    
    Algorithm:
      1. Let R = 2**2048.
      2. Interpret the input as an integer N via int.from_bytes().
      3. Compute N_inv = gmpy2.invert(N, R).
      4. Compute N_adjusted = (N_inv * (R - 1)) % R.
      5. Return N_adjusted as a 256-byte buffer.
      
    If the inverse does not exist, returns None.
    """
    if len(data) != 256:
        raise ValueError("Input data must be exactly 256 bytes.")
    
    N = int.from_bytes(data)
    R = 2 ** 2048
    
    try:
        N_inv = int(gmpy2.invert(N, R))
    except ZeroDivisionError:
        # gmpy2.invert raises ZeroDivisionError if no inverse exists.
        return None
    
    N_adjusted = (N_inv * (R - 1)) % R
    return N_adjusted.to_bytes(256)

def main():
    parser = argparse.ArgumentParser(
        description="Compute the adjusted Montgomery inverse (using gmpy2) of a 256-byte input buffer."
    )
    parser.add_argument("file", help="Path to the file containing the 256-byte buffer.")
    args = parser.parse_args()
    
    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except Exception as e:
        print("Error reading file:", e, file=sys.stderr)
        sys.exit(1)
    
    if len(data) != 256:
        print("Error: File must contain exactly 256 bytes.", file=sys.stderr)
        sys.exit(1)
    
    result = montgomery_inverse_gmpy2(data)
    if result is None:
        print("Montgomery inverse does not exist for the provided input.")
    else:
        print("Adjusted Montgomery inverse (hex):")
        print(result.hex())

if __name__ == "__main__":
    main()
