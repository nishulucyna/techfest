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

    # Configure logging for OQS output
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
    key = get_random_bytes(32)  # 256-bit AES key
    iv = get_random_bytes(16)   # 128-bit IV
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
    salt = get_random_bytes(16)
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

    return salt + encrypted_key  # Prepend salt

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

# --- Kyber Key Encapsulation ---
def perform_kyber_encapsulation(kemalg: str = "ML-KEM-1024"):
    logger.info("\n--- Kyber Encapsulation Process ---")
    try:
        with oqs.KeyEncapsulation(kemalg) as client:
            with oqs.KeyEncapsulation(kemalg) as server:
                logger.info("Using KEM algorithm: %s", kemalg)
                public_key_client = client.generate_keypair()
                kyber_client_secret_key = client.export_secret_key()
                kyber_ciphertext, kyber_shared_secret_server = server.encap_secret(public_key_client)
                kyber_shared_secret_client = client.decap_secret(kyber_ciphertext)

            logger.info("Shared secrets coincide: %s", kyber_shared_secret_client == kyber_shared_secret_server)
            if kyber_shared_secret_client != kyber_shared_secret_server:
                raise ValueError("Kyber shared secrets do not match!")

            return {
                "client_secret_key": kyber_client_secret_key,
                "ciphertext": kyber_ciphertext,
                "shared_secret": kyber_shared_secret_client
            }

    except Exception as e:
        logger.error(f"An error occurred during Kyber encapsulation: {e}")
        raise

# --- Dilithium Signature ---
def perform_dilithium_signature(data_to_sign: bytes, sigalg: str = "ML-DSA-65"):
    logger.info("\n--- Dilithium Signature Process ---")
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

# --- Main Orchestration ---
def main():
    print("--- Full Hybrid Encryption with Dilithium Signatures (Using HKDF) ---")
    message_to_encrypt = input("Enter the message to encrypt with AES: ")

    try:
        aes_encryption_results = encrypt_aes256_cbc(message_to_encrypt)
        aes_key = aes_encryption_results["key"]
        aes_iv = aes_encryption_results["iv"]
        aes_ciphertext = aes_encryption_results["ciphertext"]
        print("Initial AES Encryption Successful!")

    except Exception as e:
        print(f"\nAn error occurred during AES encryption: {e}")
        sys.exit(1)

    print("\n[STEP 2: Kyber Key Encapsulation]")
    try:
        kyber_results = perform_kyber_encapsulation()
        kyber_client_secret_key = kyber_results["client_secret_key"]
        kyber_ciphertext = kyber_results["ciphertext"]
        kyber_shared_secret = kyber_results["shared_secret"]
        print("Kyber Key Encapsulation Successful! Shared Secrets Match!")

    except Exception as e:
        print(f"\nAn error occurred during Kyber encapsulation: {e}")
        sys.exit(1)

    print("\n[STEP 3: Encrypt AES Key Using HKDF]")
    try:
        iv_for_key_encryption = get_random_bytes(16)
        encrypted_aes_key = encrypt_aes256_cbc_key_with_hkdf(
            aes_key, kyber_shared_secret, iv_for_key_encryption
        )
        print("AES Key Encryption with HKDF Successful!")

    except Exception as e:
        print(f"\nAn error occurred during AES key encryption: {e}")
        sys.exit(1)

    print("\n[STEP 4: Dilithium Signature of Encrypted Payload]")
    try:
        # Prepare the package for signing: concatenate all important parts
        package_to_sign = kyber_ciphertext + iv_for_key_encryption + encrypted_aes_key + aes_iv + aes_ciphertext
        dilithium_results = perform_dilithium_signature(package_to_sign)
        dilithium_signature = dilithium_results["signature"]
        dilithium_public_key = dilithium_results["public_key"]
        print("Dilithium Signature Successful!")

    except Exception as e:
        print(f"\nAn error occurred during Dilithium signature: {e}")
        sys.exit(1)

    # --- Display Data to Transmit ---
    print("\n--- Data to Transmit ---")
    print("Kyber Client Secret Key:", base64.b64encode(kyber_client_secret_key).decode())
    print("Kyber Ciphertext:", base64.b64encode(kyber_ciphertext).decode())
    print("IV for AES Key Encryption:", base64.b64encode(iv_for_key_encryption).decode())
    print("Encrypted AES Key:", base64.b64encode(encrypted_aes_key).decode())
    print("AES IV for Message:", base64.b64encode(aes_iv).decode())
    print("AES Ciphertext of Message:", base64.b64encode(aes_ciphertext).decode())
    print("Dilithium Public Key:", base64.b64encode(dilithium_public_key).decode())
    print("Dilithium Signature:", base64.b64encode(dilithium_signature).decode())

    # --- Decryption Part ---
    print("\n--- Decryption Process ---")

    print("\n[STEP 5: Verify Dilithium Signature]")
    try:
        package_to_verify = kyber_ciphertext + iv_for_key_encryption + encrypted_aes_key + aes_iv + aes_ciphertext
        with oqs.Signature("ML-DSA-65") as verifier:
            is_signature_valid = verifier.verify(package_to_verify, dilithium_signature, dilithium_public_key)
        print("Dilithium Signature Verification:", is_signature_valid)
        if not is_signature_valid:
            print("\n[ERROR] Signature invalid! Aborting decryption.")
            sys.exit(1)

    except Exception as e:
        print(f"\nAn error occurred during signature verification: {e}")
        sys.exit(1)

    print("\n[STEP 6: Decrypt AES Key Using HKDF]")
    try:
        decrypted_aes_key = decrypt_aes256_cbc_key_with_hkdf(
            encrypted_aes_key, kyber_shared_secret, iv_for_key_encryption
        )
        print("Decrypted AES Key Successful!")
    except Exception as e:
        print(f"\nAn error occurred during AES key decryption: {e}")
        sys.exit(1)

    print("\n[STEP 7: Decrypt AES Message]")
    try:
        decrypted_message = decrypt_aes256_cbc(aes_ciphertext, decrypted_aes_key, aes_iv)
        print("Decrypted Message:", decrypted_message)
    except Exception as e:
        print(f"\nAn error occurred during AES message decryption: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()