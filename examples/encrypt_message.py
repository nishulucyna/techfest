import os
import base64
import sys
import logging
from pprint import pformat
from sys import stdout

# Import necessary cryptographic modules directly
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad # Import pad and unpad directly

# Import OQS Kyber module directly
try:
    import oqs

    # Configure logging for OQS output (optional, but helpful for debugging)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    # Avoid adding handler multiple times if this script were imported elsewhere (though not intended)
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler(stdout))

except ImportError:
    print("\nError: Could not import the 'oqs' module.")
    print("Please ensure the 'oqspy' library is installed (`pip install oqspy`).")
    sys.exit(1) # Exit with an error code if oqs module cannot be imported

# --- AES Encryption/Decryption Functions ---
# AES Encryption of Message (using random key and IV)
def encrypt_aes256_cbc(message: str):
    """
    Encrypts plaintext using AES-256 in CBC mode with a randomly generated key and IV.

    Args:
        plaintext (str): The string to encrypt.

    Returns:
        dict: A dictionary containing the key, IV, and ciphertext in bytes.
    """
    # Generate 256-bit AES key (32 bytes)
    key = get_random_bytes(32)

    # Generate 128-bit IV (16 bytes)
    iv = get_random_bytes(16)

    # Prepare cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt with padding
    # Ensure plaintext is encoded to bytes before padding
    padded_data = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    # Return bytes directly
    return {
        "key": key,
        "iv": iv,
        "ciphertext": ciphertext
    }

# AES Decryption of Message
def decrypt_aes256_cbc(ciphertext: bytes, key: bytes, iv: bytes):
    """
    Decrypts AES-256 CBC ciphertext.

    Args:
        ciphertext (bytes): The ciphertext to decrypt.
        key (bytes): The AES key used for encryption.
        iv (bytes): The IV used for encryption.

    Returns:
        str: The decrypted and unpadded plaintext message.
    Raises:
        ValueError: If decryption or unpadding fails.
    """
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded_data, AES.block_size)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        # Handle potential decryption or padding errors
        raise ValueError(f"Decryption failed: {e}")


# Encrypt AES Key using Kyber Shared Secret (Directly - No HKDF)
def encrypt_aes256_cbc_key(aes_key_bytes: bytes, shared_secret_bytes: bytes, iv_bytes: bytes):
    """
    Encrypts the original AES key using the Kyber shared secret directly as the AES key.
    NOTE: Using the shared secret directly is NOT recommended practice. HKDF should be used.

    Args:
        aes_key_bytes (bytes): The original AES key bytes to encrypt.
        shared_secret_bytes (bytes): The Kyber shared secret bytes (used directly as key).
        iv_bytes (bytes): The IV bytes for this AES encryption step.

    Returns:
        bytes: The ciphertext of the original AES key.
    Raises:
        ValueError: If shared_secret_bytes is not 32 bytes (for AES-256).
    """
    if len(shared_secret_bytes) != 32:
        raise ValueError("Shared secret must be 32 bytes for direct use as AES-256 key.")

    cipher = AES.new(shared_secret_bytes, AES.MODE_CBC, iv_bytes)
    padded_key = pad(aes_key_bytes, AES.block_size)
    return cipher.encrypt(padded_key)

# Decrypt AES Key using Kyber Shared Secret (Directly - No HKDF)
def decrypt_aes256_cbc_key(encrypted_key_ciphertext: bytes, shared_secret_bytes: bytes, iv_bytes: bytes):
    """
    Decrypts the ciphertext of the original AES key using the Kyber shared secret directly.
    NOTE: Using the shared secret directly is NOT recommended practice. HKDF should be used.

    Args:
        encrypted_key_ciphertext (bytes): The ciphertext of the original AES key.
        shared_secret_bytes (bytes): The Kyber shared secret bytes (used directly as key).
        iv_bytes (bytes): The IV bytes for this AES decryption step.

    Returns:
        bytes: The original AES key bytes.
    Raises:
        ValueError: If shared_secret_bytes is not 32 bytes (for AES-256), or decryption fails.
    """
    if len(shared_secret_bytes) != 32:
        raise ValueError("Shared secret must be 32 bytes for direct use as AES-256 key.")

    try:
        cipher = AES.new(shared_secret_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_padded_key = cipher.decrypt(encrypted_key_ciphertext)
        original_aes_key_bytes = unpad(decrypted_padded_key, AES.block_size)
        return original_aes_key_bytes
    except (ValueError, KeyError) as e:
        # Handle potential decryption or padding errors
        raise ValueError(f"AES key decryption failed: {e}")


# --- Kyber Key Encapsulation Function ---
# Performs actual Kyber encapsulation using oqs library
def perform_kyber_encapsulation(kemalg: str = "ML-KEM-1024"):
    """
    Performs Kyber key encapsulation for a given KEM algorithm using the oqs library.
    Generates client keypair, server encapsulates, client decapsulates
    for verification, and returns the necessary bytes results.

    Args:
        kemalg (str): The name of the Kyber KEM algorithm (default is "ML-KEM-1024").

    Returns:
        dict: A dictionary containing the client secret key (bytes),
              ciphertext (bytes), and the shared secret (from client decapsulation - bytes).
    Raises:
        ValueError: If the shared secret, client secret key, or ciphertext are not generated or don't match.
        Exception: For any errors during the OQS operations.
    """
    logger.info("\n--- Kyber Encapsulation Process ---")

    kyber_shared_secret_client = None
    kyber_ciphertext = None
    kyber_client_secret_key = None

    try:
        # Create client and server with the specified KEM mechanism
        with oqs.KeyEncapsulation(kemalg) as client:
            with oqs.KeyEncapsulation(kemalg) as server:
                logger.info("Using KEM algorithm: %s", kemalg)
                logger.info("Key encapsulation details:\n%s", pformat(client.details))

                # Client generates its keypair
                # We need the client's secret key for decryption later
                public_key_client = client.generate_keypair()
                kyber_client_secret_key = client.export_secret_key() # Export client's secret key

                # The server encapsulates its secret using the client's public key
                # This generates the Kyber ciphertext and the server's copy of the shared secret
                kyber_ciphertext, kyber_shared_secret_server = server.encap_secret(public_key_client)

                # For verification/completeness, let the client decapsulate
                # to get their copy of the shared secret. This is the one we'll return.
                kyber_shared_secret_client = client.decap_secret(kyber_ciphertext)

            # Verify that client and server shared secrets match (optional but good practice)
            logger.info(
                "Shared secretes coincide: %s",
                kyber_shared_secret_client == kyber_shared_secret_server,
            )
            if kyber_shared_secret_client != kyber_shared_secret_server:
                 raise ValueError("Kyber shared secrets do not coincide!")


            if kyber_shared_secret_client is None:
                 raise ValueError("Kyber shared secret was not generated by the client.")
            if kyber_client_secret_key is None:
                 raise ValueError("Kyber client secret key was not exported.")
            if kyber_ciphertext is None:
                 raise ValueError("Kyber ciphertext was not generated.")


            logger.info("Kyber encapsulation process completed successfully.")

            # Return the necessary bytes values
            return {
                "client_secret_key": kyber_client_secret_key, # Return bytes
                "ciphertext": kyber_ciphertext,               # Return bytes
                "shared_secret": kyber_shared_secret_client   # Return bytes
            }

    except Exception as e:
        logger.error(f"An error occurred during Kyber encapsulation: {e}")
        raise # Re-raise the exception


# --- Main Function to Orchestrate ---
def main():
    """
    Performs the full hybrid encryption process (AES message encryption,
    Kyber encapsulation, AES key encryption using raw Kyber shared secret)
    and then demonstrates decryption.
    """
    print("--- Full Hybrid Encryption (AES + Kyber-based AES Key Transport - No HKDF) ---")

    # --- Step 1: Perform Initial AES Encryption on User Message ---
    print("\n[STEP 1: AES Encryption of Message]")
    message_to_encrypt = input("Enter the message to encrypt with AES: ")

    try:
        # encrypt_aes256_cbc now returns bytes
        aes_encryption_results = encrypt_aes256_cbc(message_to_encrypt)

        original_aes_key_bytes = aes_encryption_results["key"]
        original_aes_iv_bytes = aes_encryption_results["iv"]
        original_aes_ciphertext_bytes = aes_encryption_results["ciphertext"]

        # Base64 encode for display
        original_aes_key_b64 = base64.b64encode(original_aes_key_bytes).decode('utf-8')
        original_aes_iv_b64 = base64.b64encode(original_aes_iv_bytes).decode('utf-8')
        original_aes_ciphertext_b64 = base64.b64encode(original_aes_ciphertext_bytes).decode('utf-8')

        print("Initial AES Encryption Successful!")
        print("AES IV (for message)     :", original_aes_iv_b64)
        print("Ciphertext (of message)  :", original_aes_ciphertext_b64)

    except Exception as e:
        print(f"\nAn error occurred during initial AES encryption: {e}")
        sys.exit(1) # Exit with an error code


    # --- Step 2: Perform Kyber Key Encapsulation ---
    # This establishes a shared secret to protect the original AES key.
    print("\n[STEP 2: Kyber Key Encapsulation]")

    kemalg = "ML-KEM-1024" # Using ML-KEM-1024

    try:
        # perform_kyber_encapsulation now returns bytes
        kyber_results = perform_kyber_encapsulation(kemalg)

        kyber_client_secret_key_bytes = kyber_results["client_secret_key"]
        kyber_ciphertext_bytes = kyber_results["ciphertext"]
        kyber_shared_secret_bytes = kyber_results["shared_secret"] # Get the shared secret bytes

        # Base64 encode Kyber results for display
        kyber_client_secret_key_b64 = base64.b64encode(kyber_client_secret_key_bytes).decode('utf-8')
        kyber_ciphertext_b64 = base64.b64encode(kyber_ciphertext_bytes).decode('utf-8')
        kyber_shared_secret_b64 = base64.b64encode(kyber_shared_secret_bytes).decode('utf-8') # For display only

        print("Kyber Key Encapsulation Successful!")
        print("Kyber Client Secret Key (Base64) :", kyber_client_secret_key_b64)
        print("Kyber Ciphertext (Base64)        :", kyber_ciphertext_b64)
        print("Kyber Shared Secret (Base64)     :", kyber_shared_secret_b64) # Display shared secret (for demo)


    except Exception as e:
        print(f"\nAn error occurred during Kyber key encapsulation: {e}")
        sys.exit(1) # Exit with an error code


    # --- Step 3: Encrypt the Original AES Key using Kyber Shared Secret (Directly) ---
    print("\n[STEP 3: Second AES Encryption of AES Key (Using Kyber Shared Secret)]")

    try:
        # Generate a new random IV for this final AES encryption of the AES key
        iv_for_key_encryption_bytes = get_random_bytes(16)

        # Encrypt the original AES key bytes using the Kyber shared secret directly as the key
        # encrypt_aes256_cbc_key expects bytes and returns bytes
        encrypted_aes_key_ciphertext_bytes = encrypt_aes256_cbc_key(
            original_aes_key_bytes,
            kyber_shared_secret_bytes, # Using shared secret directly
            iv_for_key_encryption_bytes
        )

        # Base64 encode the results for display and transmission
        iv_for_key_encryption_b64 = base64.b64encode(iv_for_key_encryption_bytes).decode('utf-8')
        encrypted_aes_key_ciphertext_b64 = base64.b64encode(encrypted_aes_key_ciphertext_bytes).decode('utf-8')

        print("AES Key Encryption Successful!")
        print("IV (for key encryption)             :", iv_for_key_encryption_b64)
        print("Ciphertext (of original AES key)    :", encrypted_aes_key_ciphertext_b64)


    except Exception as e:
        print(f"\nAn error occurred during the final AES key encryption: {e}")
        sys.exit(1) # Exit with an error code

    # --- Information for Decryption ---
    print("\n--- Information to Transmit for Decryption ---")
    print("Kyber Client Secret Key (Base64) :", kyber_client_secret_key_b64) # Needed for decapsulation
    print("Kyber Ciphertext (Base64)        :", kyber_ciphertext_b64)       # Needed for decapsulation
    print("IV (for key encryption) (Base64) :", iv_for_key_encryption_b64)  # Needed for key decryption
    print("Ciphertext (of original AES key) (Base64):", encrypted_aes_key_ciphertext_b64) # Needed for key decryption
    print("AES IV (for message) (Base64)    :", original_aes_iv_b64)      # Needed for message decryption
    print("Ciphertext (of message) (Base64) :", original_aes_ciphertext_b64) # Needed for message decryption
    print("--------------------------------------------")

    # --- Demonstration of Decryption (within the same script) ---
    print("\n--- Demonstrating Decryption ---")

    # Step 4: Decrypt AES key using Kyber shared secret (simulated client side)
    print("\n[STEP 4: Decrypt AES Key (Using Raw Kyber Shared Secret)]")
    try:
        # In a real scenario, the recipient would use their Kyber private key
        # and the received Kyber ciphertext to perform decapsulation and get the shared secret.
        # Here, we use the shared secret obtained in Step 2 directly for demo purposes.
        decrypted_aes_key_bytes = decrypt_aes256_cbc_key(
            encrypted_aes_key_ciphertext_bytes, # Use bytes ciphertext
            kyber_shared_secret_bytes,          # Use bytes shared secret
            iv_for_key_encryption_bytes         # Use bytes IV
        )
        decrypted_aes_key_b64 = base64.b64encode(decrypted_aes_key_bytes).decode('utf-8')
        print("Decrypted AES Key (Base64) :", decrypted_aes_key_b64)

    except Exception as e:
        print(f"\nAn error occurred during AES key decryption: {e}")
        sys.exit(1)


    # Step 5: Decrypt message using the recovered AES key
    print("\n[STEP 5: Decrypt Message]")
    try:
        decrypted_message = decrypt_aes256_cbc(
            original_aes_ciphertext_bytes, # Use bytes ciphertext
            decrypted_aes_key_bytes,       # Use bytes decrypted key
            original_aes_iv_bytes          # Use bytes IV
        )
        print("Final Decrypted Message    :", decrypted_message)

    except Exception as e:
        print(f"\nAn error occurred during message decryption: {e}")
        sys.exit(1)


# Run main
if __name__ == "__main__":
    main()
