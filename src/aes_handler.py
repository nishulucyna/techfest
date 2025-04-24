import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad

# Function to encrypt a message using AES-256-CBC
def encrypt_aes256_cbc(message):
    # Generate a random AES key (32 bytes for AES-256)
    aes_key = get_random_bytes(32)
    
    # Generate a random IV (16 bytes for AES)
    iv = get_random_bytes(16)
    
    # Create AES cipher object
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Pad the message to be multiple of AES block size (16 bytes)
    padded_message = pad(message.encode(), AES.block_size)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(padded_message)
    
    # Return the ciphertext, AES key (encoded in base64), and IV (encoded in base64)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "key": base64.b64encode(aes_key).decode(),
        "iv": base64.b64encode(iv).decode()
    }

# Function to encrypt an AES key using a shared secret (AES-256-CBC encryption of the AES key)
def encrypt_aes256_cbc_key(aes_key_bytes, kyber_shared_secret_bytes, iv):
    # Generate the AES key and IV for encryption (kyber_shared_secret is the key)
    key = kyber_shared_secret_bytes[:32]  # Ensure key size is 32 bytes for AES-256
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the AES key to AES block size (16 bytes)
    padded_aes_key = pad(aes_key_bytes, AES.block_size)
    
    # Encrypt the AES key
    encrypted_key = cipher.encrypt(padded_aes_key)
    
    # Return the encrypted AES key (encoded in base64)
    return {
        "ciphertext": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode()
    }