#!/usr/bin/env python3
import os
import argparse
import sys
from Crypto.Cipher import AES

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Return the XOR of two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def left_shift_one_bit(input_bytes: bytes) -> bytes:
    """Left shift a 16-byte block by one bit."""
    as_int = int.from_bytes(input_bytes, 'big')
    shifted = (as_int << 1) & ((1 << 128) - 1)
    return shifted.to_bytes(16, 'big')

def generate_subkeys(key: bytes) -> (bytes, bytes):
    """
    Generate subkeys K1 and K2 for AES-CMAC (RFC 4493).
    K1 = (L << 1) ⊕ Rb (if MSB(L) == 1), where L = AES(key, 0^128)
    K2 = (K1 << 1) ⊕ Rb (if MSB(K1) == 1)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    const_zero = b'\x00' * 16
    L = cipher.encrypt(const_zero)
    
    K1 = left_shift_one_bit(L)
    if L[0] & 0x80:
        K1 = xor_bytes(K1, b'\x00' * 15 + b'\x87')
    
    K2 = left_shift_one_bit(K1)
    if K1[0] & 0x80:
        K2 = xor_bytes(K2, b'\x00' * 15 + b'\x87')
    
    return K1, K2

def compute_cmac(buffer: bytes, key: bytes) -> bytes:
    """
    Compute the AES-128 CMAC of a buffer whose length is a multiple of 16 bytes.
    """
    if len(buffer) % 16 != 0:
        raise ValueError("Buffer length must be a multiple of 16 bytes.")
    
    cipher = AES.new(key, AES.MODE_ECB)
    n = len(buffer) // 16
    state = b'\x00' * 16
    for i in range(n - 1):
        block = buffer[i*16:(i+1)*16]
        state = cipher.encrypt(xor_bytes(state, block))
    
    K1, _ = generate_subkeys(key)
    last_block = xor_bytes(buffer[(n-1)*16:n*16], K1)
    tag = cipher.encrypt(xor_bytes(state, last_block))
    return tag

def generate_collision_buffer(key: bytes, target_cmac: bytes) -> bytes:
    """
    Generate a 256-byte buffer (16 blocks of 16 bytes) that produces the given target CMAC
    when computed using AES-128 CMAC.
    
    The algorithm proceeds as follows:
      1. A random 256-byte buffer is generated.
      2. The first bit of the first byte and the last bit of the last byte are set.
      3. The chaining value X14 is computed from the first 14 blocks.
      4. The collision block (block 15) is calculated as:
           collision_block = X14 ⊕ AES⁻¹( AES⁻¹(target_cmac) ⊕ (M16 ⊕ K1) )
         where M16 is the final block and K1 is a subkey.
      5. The collision block is inserted into block 15, and the buffer is verified.
    
    Parameters:
      key (bytes): AES-128 key (16 bytes)
      target_cmac (bytes): Target CMAC value (16 bytes)
    
    Returns:
      bytes: The 256-byte buffer that produces the target CMAC.
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128.")
    if len(target_cmac) != 16:
        raise ValueError("Target CMAC must be 16 bytes.")
    
    # Step 1: Generate a random 256-byte buffer (16 blocks)
    buf = bytearray(os.urandom(16 * 16))
    
    # Step 2: Set the first bit of the first byte and the last bit of the last byte.
    buf[0] |= 0x80         # Set the most significant bit of the first byte.
    buf[-1] |= 0x01        # Set the least significant bit of the last byte.
    
    # Prepare AES ciphers for encryption and decryption.
    cipher_enc = AES.new(key, AES.MODE_ECB)
    cipher_dec = AES.new(key, AES.MODE_ECB)
    
    # Step 3: Compute X14 from blocks 1..14 (0-indexed blocks 0 to 13).
    X14 = b'\x00' * 16
    for i in range(14):
        block = bytes(buf[i*16:(i+1)*16])
        X14 = cipher_enc.encrypt(xor_bytes(X14, block))
    
    # Block layout:
    #   Blocks 0-13: used to compute X14.
    #   Block 14: collision block (to be computed).
    #   Block 15: final block (remains random).
    M16 = bytes(buf[15*16:16*16])  # final block
    
    # Generate subkey K1
    K1, _ = generate_subkeys(key)
    
    # Step 4: Calculate the collision block for block 15 (0-indexed block 14).
    inner = xor_bytes(cipher_dec.decrypt(target_cmac), xor_bytes(M16, K1))
    collision_block = xor_bytes(X14, cipher_dec.decrypt(inner))
    
    # Insert the computed collision block into block 15 (0-indexed block 14)
    buf[14*16:15*16] = collision_block
    
    # Step 5: Verify that the full 256-byte buffer produces the target CMAC.
    final_tag = compute_cmac(bytes(buf), key)
    if final_tag != target_cmac:
        raise ValueError("Verification failed: computed CMAC does not match target.")
    
    return bytes(buf)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a 256-byte buffer that produces a given AES-128 CMAC. "
                    "The collision block is placed in block 15 (second-to-last block)."
    )
    parser.add_argument("key", help="AES key in hexadecimal (32 hex digits for AES-128)")
    parser.add_argument("target_cmac", help="Target CMAC in hexadecimal (32 hex digits)")
    parser.add_argument("--output", "-o", help="Output file to write the 256-byte buffer", default=None)
    args = parser.parse_args()
    
    try:
        key = bytes.fromhex(args.key)
    except ValueError:
        print("Error: Invalid key hexadecimal string.", file=sys.stderr)
        sys.exit(1)
    
    try:
        target_cmac = bytes.fromhex(args.target_cmac)
    except ValueError:
        print("Error: Invalid target CMAC hexadecimal string.", file=sys.stderr)
        sys.exit(1)
    
    try:
        collision_buffer = generate_collision_buffer(key, target_cmac)
        print("Success: Generated collision buffer produces the target CMAC.")
        print("Target CMAC:", target_cmac.hex())
        if args.output:
            with open(args.output, "wb") as f:
                f.write(collision_buffer)
            print(f"Collision buffer written to {args.output}")
        else:
            print("Collision buffer (hex):")
            print(collision_buffer.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(1)
