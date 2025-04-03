from Crypto.Cipher import AES

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def left_shift_one_bit(input_bytes: bytes) -> bytes:
    """Left shift a 16-byte block by one bit."""
    as_int = int.from_bytes(input_bytes, 'big')
    shifted = (as_int << 1) & ((1 << 128) - 1)
    return shifted.to_bytes(16, 'big')

def generate_subkeys(key: bytes) -> (bytes, bytes):
    """
    Generate subkeys K1 and K2 for AES-CMAC.
    As defined in RFC4493:
      - K1 = (L << 1) ⊕ Rb (if MSB(L) == 1)
      - K2 = (K1 << 1) ⊕ Rb (if MSB(K1) == 1)
    where L = AES(key, 0^128) and Rb = 0x87 (applied to the last byte).
    """
    cipher = AES.new(key, AES.MODE_ECB)
    const_zero = b'\x00' * 16
    L = cipher.encrypt(const_zero)
    
    # Generate K1 from L
    K1 = left_shift_one_bit(L)
    if L[0] & 0x80:
        K1 = xor_bytes(K1, b'\x00' * 15 + b'\x87')
    
    # Generate K2 from K1
    K2 = left_shift_one_bit(K1)
    if K1[0] & 0x80:
        K2 = xor_bytes(K2, b'\x00' * 15 + b'\x87')
    
    return K1, K2

def aes_cmac(key: bytes, data: bytes) -> bytes:
    """
    Calculate the AES-128 CMAC for the given data.
    The data must be a multiple of 16 bytes.
    
    :param key: AES key (16 bytes)
    :param data: Data over which to compute the CMAC (must be a multiple of 16 bytes)
    :return: 16-byte CMAC tag
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long for AES-128.")
    if len(data) % 16 != 0:
        raise ValueError("Data length must be a multiple of 16 bytes.")
    
    cipher = AES.new(key, AES.MODE_ECB)
    n = len(data) // 16

    K1, _ = generate_subkeys(key)
    
    # Initialize the variable (previous cipher block) to zero.
    X = b'\x00' * 16
    
    # Process all blocks except the last.
    for i in range(n - 1):
        block = data[i*16:(i+1)*16]
        X = cipher.encrypt(xor_bytes(X, block))
    
    # For complete blocks, use subkey K1.
    last_block = data[(n - 1)*16:n*16]
    last_block = xor_bytes(last_block, K1)
    T = cipher.encrypt(xor_bytes(X, last_block))
    
    return T
