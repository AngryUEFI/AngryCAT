#!/usr/bin/env python3
import sys
import argparse

MAX_FACTOR=5000

def factor_256(data: bytes, max_factor: int):
    """
    Factor a 256-byte string interpreted as an integer into two factors.

    Steps:
      1. Interpret the input bytes as an integer using int.from_bytes().
      2. For candidate factors 2 through 5000, check if the candidate divides the integer.
      3. If a factor is found, compute the complementary factor.
      4. If no candidate factor in the range divides the integer, return None.

    Parameters:
      data (bytes): A 256-byte input.
      max_factor (int): the maximum factor to search to.

    Returns:
      tuple (int, int) or None: The two factors if found, otherwise None.
    """
    if len(data) != 256:
        raise ValueError("Input must be exactly 256 bytes.")
    
    n = int.from_bytes(data, byteorder='big')
    
    # Try potential factors from 2 to MAX_FACTOR.
    for factor in range(2, max_factor + 1):
        if n % factor == 0:
            other = n // factor
            return (factor, other)
    return None  # No factor found in the allowed range.

def main():
    parser = argparse.ArgumentParser(description="Factor a 256-byte string into two factors.")
    parser.add_argument("file", help="Path to the file containing the 256-byte string.")
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
    
    result = factor_256(data, MAX_FACTOR)
    if result is None:
        print("No valid factorization found or one of the factors is larger than 5000.")
    else:
        print(f"Factors found: 0x{result[0]:x} and 0x{result[1]:x}")

if __name__ == "__main__":
    main()
