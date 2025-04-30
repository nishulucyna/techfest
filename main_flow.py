# src/main_flow.py

import logging
import os

from src.aes_handler import AESHandler
from src.kyber_handler import encapsulate_kem, decapsulate_kem, generate_key_pair as generate_kyber_key_pair, derive_aes_key as kyber_derive_aes_key # Import derive_aes_key
from src.dilithium_handler import sign_message, verify_signature, generate_key_pair as generate_dilithium_key_pair

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def main():
    logging.basicConfig(level=logging.INFO)

    # --- Get Plaintext Input from User ---
    plaintext_input = input("Enter the plaintext to encrypt: ").encode('utf-8')
    logger.info(f"User provided plaintext (hex): {plaintext_input.hex()}")

    # --- Kyber Key Pair Generation and Encapsulation ---
    logger.info("\n--- Kyber Key Pair Generation and Encapsulation ---")
    kyber_public_key, kyber_private_key = generate_kyber_key_pair()
    derived_aes_key, salt, kyber_ciphertext = encapsulate_kem(kyber_public_key)

    if not derived_aes_key:
        logger.error("Failed to establish a secure channel using Kyber.")
        return

    logger.info("Successfully established a shared secret and derived an AES key using Kyber encapsulation.")
    logger.info(f"Salt (for HKDF): {salt.hex()}")
    logger.info(f"Kyber Ciphertext: {kyber_ciphertext.hex()}")
    logger.info(f"Derived AES Key (initial): {derived_aes_key.hex()}")
    logger.info(f"Kyber Public Key: {bytes(kyber_public_key).hex()}")
    logger.info(f"Kyber Private Key: {bytes(kyber_private_key).hex()}")

    # --- AES Encryption ---
    logger.info("\n--- AES Encryption ---")
    aes_handler = AESHandler()
    iv = os.urandom(12) # Generate IV here
    ciphertext, iv, tag = aes_handler.encrypt(plaintext_input, derived_aes_key, iv) # Pass IV to encrypt
    logger.info(f"AES Encrypted Ciphertext (hex): {ciphertext.hex()}")
    logger.info(f"AES Authentication Tag (hex): {tag.hex()}")
    logger.info(f"AES IV (hex): {iv.hex()}")

    # --- Package the Data for Signing ---
    package_to_sign = kyber_ciphertext + salt + iv + ciphertext + tag
    logger.info(f"\n--- Data Package to Sign (hex) ---")
    logger.info(f"{package_to_sign.hex()}")

    # --- Dilithium Signing ---
    logger.info("\n--- Dilithium Signing ---")
    dilithium_public_key, dilithium_private_key_bytes = generate_dilithium_key_pair() # Get bytes here
    signature = sign_message(package_to_sign, dilithium_private_key_bytes) # Pass the message and private key bytes
    logger.info(f"Message to Sign (hex): {package_to_sign.hex()}")
    logger.info(f"Dilithium Public Key: {bytes(dilithium_public_key).hex()}")
    logger.info(f"Dilithium Private Key (hex): {dilithium_private_key_bytes.hex()}") # Log bytes
    logger.info(f"Dilithium Signature: {signature.hex()}")

    # --- Simulate Transmission ---
    received_kyber_ciphertext = kyber_ciphertext
    received_salt = salt
    received_iv = iv
    received_aes_ciphertext = ciphertext
    received_tag = tag
    received_signature = signature
    received_dilithium_public_key = dilithium_public_key

    # --- Kyber Decapsulation ---
    logger.info("\n--- Kyber Decapsulation ---")
    shared_secret_decapsulated = decapsulate_kem(received_kyber_ciphertext, kyber_private_key) # Pass private key
    derived_aes_key_decapsulated = kyber_derive_aes_key(shared_secret_decapsulated, received_salt) # Call the function directly

    logger.info(f"Decapsulated Shared Secret (hex): {shared_secret_decapsulated.hex()}")
    logger.info(f"Derived AES Key (decapsulated) (hex): {derived_aes_key_decapsulated.hex()}")

    # --- AES Decryption ---
    logger.info("\n--- AES Decryption ---")
    aes_handler_decryption = AESHandler()
    try:
        decrypted_plaintext = aes_handler_decryption.decrypt(
            received_aes_ciphertext, received_iv, derived_aes_key_decapsulated, tag=received_tag # Pass the tag
        )
        logger.info(f"Decrypted Plaintext: {decrypted_plaintext.decode('utf-8')}")
    except Exception as e:
        logger.error(f"AES Decryption Error: {e}")

    # --- Dilithium Signature Verification ---
    logger.info("\n--- Dilithium Signature Verification ---")
    is_signature_valid = verify_signature(
        package_to_sign, received_signature, received_dilithium_public_key
    )
    logger.info(f"Signature verification result: {is_signature_valid}")

    if is_signature_valid:
        logger.info("Dilithium signature is valid. The package is authentic.")
    else:
        logger.error("Dilithium signature verification failed. The package is not authentic.")

if __name__ == "__main__":
    main()