from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

# PKCS7 Padding functions
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def encrypt_aes256_cbc(plaintext: str):
    # Generate 256-bit AES key (32 bytes)
    key = get_random_bytes(32)
    
    # Generate 128-bit IV (16 bytes)
    iv = get_random_bytes(16)

    # Prepare cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt with padding
    padded_data = pad(plaintext.encode())
    ciphertext = cipher.encrypt(padded_data)

    # Base64 encode all parts for display
    return {
        "key": base64.b64encode(key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

# Example usage
if __name__ == "__main__":
    message = input("Enter the message to encrypt: ")
    result = encrypt_aes256_cbc(message)
    print("\nEncrypted Output:")
    print("AES Key    :", result["key"])
    print("IV         :", result["iv"])
    print("Ciphertext :", result["ciphertext"])

