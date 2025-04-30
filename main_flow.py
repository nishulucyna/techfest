import base64
import logging
from sys import stdout
from Crypto.Random import get_random_bytes

# Import from modules
from src.aes_handler import encrypt_aes256_gcm, decrypt_aes256_gcm, derive_aes_key
from src.kyber_handler import perform_kyber_encapsulation
from src.dilithium_handler import sign_data, verify_signature
# Logger setup
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Set to INFO to suppress debug logs
if not logger.handlers:
    logger.addHandler(logging.StreamHandler(stdout))


def main():
    print("\n=== Post-Quantum Hybrid Encryption (AES-GCM + Kyber + Dilithium) ===")
    message = input("Enter the message to encrypt: ")

    # Step 1: Kyber Key Exchange
    kyber = perform_kyber_encapsulation()
    shared_secret = kyber["shared_secret"]
    ciphertext_kyber = kyber["ciphertext"]
    client_secret_key = kyber["client_secret_key"]

    # Step 2: Derive AES Key using HKDF
    salt = get_random_bytes(16)
    derived_key = derive_aes_key(shared_secret, salt)

    # Step 3: Encrypt the message
    aes = encrypt_aes256_gcm(message, derived_key)
    nonce, ciphertext, tag = aes["nonce"], aes["ciphertext"], aes["tag"]

    # Step 4: Create package to sign
    package = ciphertext_kyber + salt + nonce + tag + ciphertext

    # Step 5: Sign the package using Dilithium
    dilithium = sign_data(package)
    signature = dilithium["signature"]
    public_key = dilithium["public_key"]

    # Step 6: Transmit package
    print("\n--- Transmit This Data ---")
    print("Kyber Ciphertext:", base64.b64encode(ciphertext_kyber).decode())
    print("HKDF Salt:", base64.b64encode(salt).decode())
    print("AES Nonce:", base64.b64encode(nonce).decode())
    print("AES Tag:", base64.b64encode(tag).decode())
    print("AES Ciphertext:", base64.b64encode(ciphertext).decode())
    print("Dilithium Public Key:", base64.b64encode(public_key).decode())
    print("Dilithium Signature:", base64.b64encode(signature).decode())

    # --- Decryption Process ---
    print("\n=== Decryption & Verification ===")

    # Step 1: Verify the signature
    print("\n[Step 1] ✅ Verifying Signature...")
    is_valid = verify_signature(package, signature, public_key)
    print("Signature Valid:", is_valid)

    if not is_valid:
        print("❌ Signature verification failed. Aborting decryption.")
        return

    # Step 2: Derive AES key again using shared secret + salt
    print("\n[Step 2] Deriving AES Key using shared secret + salt...")
    derived_key = derive_aes_key(shared_secret, salt)

    # Step 3: Decrypt the ciphertext
    print("\n[Step 3] Decrypting AES-GCM Ciphertext...")
    try:
        decrypted_message = decrypt_aes256_gcm(ciphertext, derived_key, nonce, tag)
        print("\n✅ Final Decrypted Message:", decrypted_message)
    except Exception as e:
        print("❌ AES decryption failed:", e)


if __name__ == "__main__":
    main()