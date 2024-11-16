# Initial Permutation (IP) table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP) table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Permuted Choice 1 (PC-1) table for key
PC_1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted Choice 2 (PC-2) table for key
PC_2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Shift schedule for key
SHIFT_SCHEDULE = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

def permute(block, table):
    """Permute the block using the specified table."""
    return [block[i - 1] for i in table]

def xor(bits1, bits2):
    """Perform XOR on two bit arrays."""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def feistel_function(right, round_key):
    """Feistel function (simplified version)."""
    # XOR with the round key
    xor_result = xor(right, round_key)
    # Substitute using a simplified S-Box
    substituted = [xor_result[i] ^ i % 4 for i in range(len(xor_result))]  # Example substitution
    return substituted

def generate_keys(key):
    """Generate 16 round keys from the main key."""
    permuted_key = permute(key, PC_1)
    left, right = permuted_key[:28], permuted_key[28:]
    round_keys = []
    for shift in SHIFT_SCHEDULE:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        round_keys.append(permute(left + right, PC_2))
    return round_keys

def des_encrypt(plaintext, key):
    """Encrypt plaintext using DES."""
    plaintext_bits = [int(b) for b in ''.join(format(ord(c), '08b') for c in plaintext)]
    key_bits = [int(b) for b in ''.join(format(ord(c), '08b') for c in key)]
    
    # Apply initial permutation
    permuted_text = permute(plaintext_bits, IP)
    left, right = permuted_text[:32], permuted_text[32:]
    
    # Generate round keys
    round_keys = generate_keys(key_bits)
    
    # Perform 16 rounds
    for round_key in round_keys:
        temp = right
        right = xor(left, feistel_function(right, round_key))
        left = temp
    
    # Apply final permutation
    final_text = permute(right + left, FP)
    return ''.join(map(str, final_text))

def des_decrypt(ciphertext, key):
    """Decrypt ciphertext using DES."""
    ciphertext_bits = [int(b) for b in ciphertext]
    key_bits = [int(b) for b in ''.join(format(ord(c), '08b') for c in key)]
    
    # Apply initial permutation
    permuted_text = permute(ciphertext_bits, IP)
    left, right = permuted_text[:32], permuted_text[32:]
    
    # Generate round keys
    round_keys = generate_keys(key_bits)
    
    # Perform 16 rounds in reverse order
    for round_key in reversed(round_keys):
        temp = right
        right = xor(left, feistel_function(right, round_key))
        left = temp
    
    # Apply final permutation
    final_text = permute(right + left, FP)
    return ''.join(map(str, final_text))

# Example usage
plaintext = "hello123"  # 8-character plaintext
key = "mysecret"        # 8-character key
ciphertext = des_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")

decrypted_bits = des_decrypt(ciphertext, key)
decrypted_text = ''.join(chr(int(decrypted_bits[i:i+8], 2)) for i in range(0, len(decrypted_bits), 8))
print(f"Decrypted Text: {decrypted_text}")  # Should match "ABCDEFGH"
