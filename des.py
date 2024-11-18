import string
# Permutation tables and constants
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

SHIFT_SCHEDULE = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

def permute(block, table):
    return [block[i - 1] for i in table]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def feistel_function(right, round_key):
    return xor(right, round_key)

def text_to_bits(text):
    return [int(b) for b in ''.join(format(ord(c), '08b') for c in text)]

def bits_to_text(bits):
    return ''.join(chr(int(''.join(map(str, bits[i:i + 8])), 2)) for i in range(0, len(bits), 8))

def pad(text):
    padding_length = 8 - (len(text) % 8)
    return text + chr(padding_length) * padding_length

def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

def generate_keys(key):
    key_bits = text_to_bits(key)
    permuted_key = permute(key_bits, PC_1)
    left, right = permuted_key[:28], permuted_key[28:]
    round_keys = []
    for shift in SHIFT_SCHEDULE:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        round_keys.append(permute(left + right, PC_2))
    return round_keys

def des_encrypt(plaintext, key):
    plaintext = pad(plaintext)
    blocks = [plaintext[i:i + 8] for i in range(0, len(plaintext), 8)]
    round_keys = generate_keys(key)
    ciphertext = ""
    for block in blocks:
        bits = text_to_bits(block)
        permuted_bits = permute(bits, IP)
        left, right = permuted_bits[:32], permuted_bits[32:]
        for round_key in round_keys:
            left, right = right, xor(left, feistel_function(right, round_key))
        ciphertext += bits_to_text(permute(right + left, FP))
    return ciphertext

def remove_non_printable(input_string):
    # Create a translation table with printable characters only
    printable = set(string.printable)
    # Filter out non-printable characters
    cleaned_string = ''.join(filter(lambda x: x in printable, input_string))
    return cleaned_string

def des_decrypt(ciphertext, key):
    blocks = [ciphertext[i:i + 8] for i in range(0, len(ciphertext), 8)]
    round_keys = generate_keys(key)
    plaintext = ""
    for block in blocks:
        bits = text_to_bits(block)
        permuted_bits = permute(bits, IP)
        left, right = permuted_bits[:32], permuted_bits[32:]
        for round_key in reversed(round_keys):
            left, right = right, xor(left, feistel_function(right, round_key))
        plaintext += bits_to_text(permute(right + left, FP))
    return unpad(plaintext)

# Example Usage
# plaintext = """Information security covers the tools and processes that organizations use to protect 
# information. This includes policy settings that prevent unauthorized people from accessing 
# business or personal information. InfoSec is a growing and evolving field that covers a wide 
# range of fields, from network and infrastructure security to testing and auditing. Information 
# security protects sensitive information from unauthorized activities, including inspection, 
# modification, recording, and any disruption or destruction. The goal is to ensure the safety 
# and privacy of critical data such as customer account details, financial data or intellectual 
# property. The consequences of security incidents include theft of private information, data 
# tampering, and data deletion. Attacks can disrupt work processes and damage a company's 
# reputation, and also have a tangible cost. Organizations must allocate funds for security and 
# ensure that they are ready to detect, respond to, and proactively prevent, attacks such as 
# phishing, malware, viruses, malicious insiders, and ransomware."""

# key = "mysecret"  # 8-character key

# ciphertext = des_encrypt(plaintext, key)
# print("Ciphertext:", ciphertext)

# decrypted_text = des_decrypt(ciphertext, key)
# print("Decrypted Text:", decrypted_text)
