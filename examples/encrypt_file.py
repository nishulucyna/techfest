import os
import base64
import sys
import logging
from pprint import pformat
from sys import stdout
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Import OQS Kyber and Dilithium modules directly
try:
    import oqs

    # Configure logging for OQS output (optional, but helpful for debugging)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler(stdout))

except ImportError:
    print("\nError: Could not import the 'oqs' module.")
    print("Please ensure the 'oqspy' library is installed (`pip install oqspy`).")
    sys.exit(1)

# --- AES Encryption/Decryption Functions ---
def encrypt_aes256_cbc(message: str):
    key = get_random_bytes(32)   # Generate 256-bit AES key (32 bytes)
    iv = get_random_bytes(16)    # Generate 128-bit IV (16 bytes)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return {
        "key": key,
        "iv": iv,
        "ciphertext": ciphertext
    }

def decrypt_aes256_cbc(ciphertext: bytes, key: bytes, iv: bytes):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded_data, AES.block_size)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        raise ValueError(f"Decryption failed: {e}")

# --- AES Key Encryption Using HKDF with Random Salt ---
def encrypt_aes256_cbc_key_with_hkdf(aes_key_bytes: bytes, shared_secret_bytes: bytes, iv_bytes: bytes):
    salt = get_random_bytes(16)  # Random 16-byte salt
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"AES encryption",
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_secret_bytes)

    cipher = AES.new(derived_key, AES.MODE_CBC, iv_bytes)
    padded_key = pad(aes_key_bytes, AES.block_size)
    encrypted_key = cipher.encrypt(padded_key)

    return salt + encrypted_key  # Prepend salt to ciphertext

def decrypt_aes256_cbc_key_with_hkdf(encrypted_key_ciphertext: bytes, shared_secret_bytes: bytes, iv_bytes: bytes):
    salt = encrypted_key_ciphertext[:16]
    ciphertext = encrypted_key_ciphertext[16:]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"AES encryption",
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_secret_bytes)

    try:
        cipher = AES.new(derived_key, AES.MODE_CBC, iv_bytes)
        decrypted_padded_key = cipher.decrypt(ciphertext)
        original_aes_key_bytes = unpad(decrypted_padded_key, AES.block_size)
        return original_aes_key_bytes
    except (ValueError, KeyError) as e:
        raise ValueError(f"AES key decryption failed: {e}")

# --- Kyber Key Encapsulation Function ---
def perform_kyber_encapsulation(kemalg: str = "ML-KEM-1024"):
    logger.info("\n--- Kyber Encapsulation Process ---")
    kyber_shared_secret_client = None
    kyber_ciphertext = None
    kyber_client_secret_key = None
    try:
        with oqs.KeyEncapsulation(kemalg) as client:
            with oqs.KeyEncapsulation(kemalg) as server:
                logger.info("Using KEM algorithm: %s", kemalg)
                public_key_client = client.generate_keypair()
                kyber_client_secret_key = client.export_secret_key()
                kyber_ciphertext, kyber_shared_secret_server = server.encap_secret(public_key_client)
                kyber_shared_secret_client = client.decap_secret(kyber_ciphertext)

            logger.info("Shared secretes coincide: %s", kyber_shared_secret_client == kyber_shared_secret_server)
            if kyber_shared_secret_client != kyber_shared_secret_server:
                raise ValueError("Kyber shared secrets do not coincide!")

            return {
                "client_secret_key": kyber_client_secret_key,
                "ciphertext": kyber_ciphertext,
                "shared_secret": kyber_shared_secret_client
            }

    except Exception as e:
        logger.error(f"An error occurred during Kyber encapsulation: {e}")
        raise

# --- Dilithium Signature Functions ---
def perform_dilithium_signature(data_to_sign: bytes, sigalg: str = "ML-DSA-65"):
    logger.info("\n--- Dilithium Signature Process ---")
    signature_bytes = None
    public_key_bytes = None
    private_key_bytes = None
    is_valid = False
    try:
        with oqs.Signature(sigalg) as signer:
            public_key_bytes = signer.generate_keypair()
            private_key_bytes = signer.export_secret_key()
            signature_bytes = signer.sign(data_to_sign)

        with oqs.Signature(sigalg) as verifier:
            is_valid = verifier.verify(data_to_sign, signature_bytes, public_key_bytes)

        return {
            "signature": signature_bytes,
            "public_key": public_key_bytes,
            "private_key": private_key_bytes,
            "is_valid": is_valid
        }

    except Exception as e:
        logger.error(f"An error occurred during Dilithium signature: {e}")
        raise

# --- Main Function to Orchestrate ---
def main():
    print("--- Full Hybrid Encryption with Dilithium Signatures (Using HKDF) ---")
    message_to_encrypt = input("Enter the message to encrypt with AES: ")

    try:
        aes_encryption_results = encrypt_aes256_cbc(message_to_encrypt)
        original_aes_key_bytes = aes_encryption_results["key"]
        original_aes_iv_bytes = aes_encryption_results["iv"]
        original_aes_ciphertext_bytes = aes_encryption_results["ciphertext"]
        original_aes_key_b64 = base64.b64encode(original_aes_key_bytes).decode('utf-8')
        original_aes_iv_b64 = base64.b64encode(original_aes_iv_bytes).decode('utf-8')
        original_aes_ciphertext_b64 = base64.b64encode(original_aes_ciphertext_bytes).decode('utf-8')
        print("Initial AES Encryption Successful!")
        print("AES IV (for message)     :", original_aes_iv_b64)
        print("Ciphertext (of message)  :", original_aes_ciphertext_b64)

    except Exception as e:
        print(f"\nAn error occurred during initial AES encryption: {e}")
        sys.exit(1)

    print("\n[STEP 2: Kyber Key Encapsulation]")
    kemalg = "ML-KEM-1024"
    try:
        kyber_results = perform_kyber_encapsulation(kemalg)
        kyber_client_secret_key_bytes = kyber_results["client_secret_key"]
        kyber_ciphertext_bytes = kyber_results["ciphertext"]
        kyber_shared_secret_bytes = kyber_results["shared_secret"]
        print("Kyber Key Encapsulation Successful!")

    except Exception as e:
        print(f"\nAn error occurred during Kyber key encapsulation: {e}")
        sys.exit(1)

    print("\n[STEP 3: Encrypt AES Key Using HKDF]")
    try:
        iv_for_key_encryption_bytes = get_random_bytes(16)
        encrypted_aes_key_ciphertext_bytes = encrypt_aes256_cbc_key_with_hkdf(
            original_aes_key_bytes,
            kyber_shared_secret_bytes,
            iv_for_key_encryption_bytes
        )
        iv_for_key_encryption_b64 = base64.b64encode(iv_for_key_encryption_bytes).decode('utf-8')
        encrypted_aes_key_ciphertext_b64 = base64.b64encode(encrypted_aes_key_ciphertext_bytes).decode('utf-8')
        print("AES Key Encryption with HKDF Successful!")

    except Exception as e:
        print(f"\nAn error occurred during the final AES key encryption: {e}")
        sys.exit(1)

    print("\n[STEP 4: Dilithium Signature of Encrypted Message]")
    try:
        dilithium_results = perform_dilithium_signature(original_aes_ciphertext_bytes)
        dilithium_signature_bytes = dilithium_results["signature"]
        dilithium_public_key_bytes = dilithium_results["public_key"]
        dilithium_private_key_bytes = dilithium_results["private_key"]
        dilithium_signature_b64 = base64.b64encode(dilithium_signature_bytes).decode('utf-8')
        dilithium_public_key_b64 = base64.b64encode(dilithium_public_key_bytes).decode('utf-8')
        dilithium_private_key_b64 = base64.b64encode(dilithium_private_key_bytes).decode('utf-8')
        print("Dilithium Signature Successful!")

    except Exception as e:
        print(f"\nAn error occurred during Dilithium signature: {e}")
        sys.exit(1)

    print("\n--- Information to Transmit for Decryption and Verification ---")
    print("Kyber Client Secret Key (Base64) :", base64.b64encode(kyber_client_secret_key_bytes).decode('utf-8'))
    print("Kyber Ciphertext (Base64)         :", base64.b64encode(kyber_ciphertext_bytes).decode('utf-8'))
    print("IV (for key encryption) (Base64) :", iv_for_key_encryption_b64)
    print("Ciphertext (of original AES key) (Base64):", encrypted_aes_key_ciphertext_b64)
    print("AES IV (for message) (Base64)     :", original_aes_iv_b64)
    print("Ciphertext (of message) (Base64) :", original_aes_ciphertext_b64)
    print("Dilithium Public Key (Base64)     :", dilithium_public_key_b64)
    print("Dilithium Signature (Base64)     :", dilithium_signature_b64)

    # --- Decryption Part ---
    print("\n--- Decryption Process ---")
    print("[STEP 5: Decrypt AES Key Using HKDF]")
    try:
        decrypted_aes_key_bytes = decrypt_aes256_cbc_key_with_hkdf(
            encrypted_aes_key_ciphertext_bytes,
            kyber_shared_secret_bytes,
            iv_for_key_encryption_bytes
        )
        print("Decrypted AES Key Using HKDF Successful!")
    except Exception as e:
        print(f"\nAn error occurred during AES key decryption: {e}")
        sys.exit(1)

    print("\n[STEP 6: Decapsulate Kyber Key]")
    kyber_shared_secret_decrypted = kyber_shared_secret_bytes
    print("Kyber Key Decapsulation (simulated) Successful!")
    print("Shared Secret Matches: ", kyber_shared_secret_bytes == kyber_shared_secret_decrypted)

    print("\n[STEP 7: Decrypt AES Message]")
    try:
        decrypted_message = decrypt_aes256_cbc(original_aes_ciphertext_bytes, decrypted_aes_key_bytes, original_aes_iv_bytes)
        print("Decrypted Message:", decrypted_message)
    except Exception as e:
        print(f"\nAn error occurred during AES message decryption: {e}")
        sys.exit(1)

    print("\n[STEP 8: Verify Dilithium Signature]")
    try:
        is_signature_valid = False
        with oqs.Signature("ML-DSA-65") as verifier:
            is_signature_valid = verifier.verify(original_aes_ciphertext_bytes, dilithium_signature_bytes, dilithium_public_key_bytes)
        print("Dilithium Signature Verification: ", is_signature_valid)
    except Exception as e:
        print(f"\nAn error occurred during Dilithium signature verification: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
