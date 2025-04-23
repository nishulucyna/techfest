import sys
import os
import base64
# No need to import oqs, logging, pprint, stdout directly here anymore
# as they are handled within kyber_handler.py

# --- Configure System Path for Module Imports ---
# This finds the directory where the current script (main_program.py) is located,
# goes up one level (os.pardir), and then constructs the path to the 'src' directory.
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.join(current_dir, os.pardir) # This goes up to \techfest
src_dir = os.path.join(parent_dir, 'src')       # This goes into \techfest\src

# Add the src directory to sys.path
sys.path.insert(0, src_dir)

# --- Import the AES Handler Module ---
# Python can now find 'src' because it's in sys.path, and then look inside it.
try:
    # Assuming your AES module is named aes_handler.py and contains encrypt_aes256_cbc
    from aes_handler import encrypt_aes256_cbc
except ImportError:
    print(f"Error: Could not import the 'encrypt_aes256_cbc' function from '{src_dir}/aes_handler.py'.")
    print("Please ensure 'aes_handler.py' exists in that directory.")
    # It's good practice to remove the added path if the import fails, though exit() handles it here.
    if src_dir in sys.path:
         sys.path.remove(src_dir)
    exit() # Exit if the module cannot be imported

# --- Import the Kyber Handler Module ---
# Assuming your Kyber module is named kyber_handler.py and contains the
# perform_kyber_encapsulation function.
try:
    from kyber_handler import perform_kyber_encapsulation
except ImportError:
    print(f"Error: Could not import the 'perform_kyber_encapsulation' function from '{src_dir}/kyber_handler.py'.")
    print("Please ensure 'kyber_handler.py' exists in that directory and contains the function.")
    # Clean up sys.path before exiting if import fails
    if src_dir in sys.path:
         sys.path.remove(src_dir)
    exit() # Exit if the module cannot be imported

def main():
    """
    Performs AES encryption on a user message and then performs Kyber key
    encapsulation using the handler function. Outputs the results of both steps.
    """
    print("--- AES Encryption and Kyber Key Encapsulation ---")

    # --- Step 1: Perform Initial AES Encryption on User Message ---
    print("\nPerforming initial AES encryption on user message...")

    message_to_encrypt = input("Enter the message to encrypt with AES: ")

    try:
        # Use the imported AES function to encrypt the user's message
        aes_encryption_result = encrypt_aes256_cbc(message_to_encrypt)

        # Extract the base64 encoded results
        original_aes_key_b64 = aes_encryption_result["key"]
        original_aes_iv_b64 = aes_encryption_result["iv"]
        original_aes_ciphertext_b64 = aes_encryption_result["ciphertext"]

        print("\nInitial AES Encryption Successful!")
        print("AES Key (for message)    :", original_aes_key_b64)
        print("AES IV (for message)     :", original_aes_iv_b64)
        print("Ciphertext (of message)  :", original_aes_ciphertext_b64)

    except Exception as e:
        print(f"\nAn error occurred during initial AES encryption: {e}")
        # Clean up sys.path before exiting
        if src_dir in sys.path:
             sys.path.remove(src_dir)
        exit() # Exit if initial AES encryption fails

    # --- Step 2: Perform Kyber Key Encapsulation ---
    # Use the imported Kyber function to perform the encapsulation.
    print("\nPerforming Kyber Key Encapsulation...")

    kemalg = "ML-KEM-512" # Using ML-KEM-512

    try:
        # Call the function from kyber_handler
        kyber_results = perform_kyber_encapsulation(kemalg)

        kyber_client_secret_key_b64 = kyber_results["client_secret_key"]
        kyber_ciphertext_b64 = kyber_results["ciphertext"]
        # Get the shared secret from the function's return
        kyber_shared_secret_b64 = kyber_results["shared_secret"]

        print("Kyber Key Encapsulation Successful!")
        print("\n--- Information for Decryption Program ---")
        print("Kyber Client Secret Key (Base64) :", kyber_client_secret_key_b64)
        print() # Added newline for readability
        print("Kyber Ciphertext (Base64)        :", kyber_ciphertext_b64)
        print() # Added newline for readability
        # Outputting the shared secret derived by the client in the handler function
        print("Kyber Shared Secret (Client-Derived) (Base64):", kyber_shared_secret_b64)
        print("------------------------------------------")

        # Output the AES results again here for easy copy-pasting alongside Kyber results
        print("\n--- Information for Decryption Program (cont.) ---")
        print("AES Key (for message)    :", original_aes_key_b64) # Note: This key is NOT encrypted by Kyber in this version
        print("AES IV (for message)     :", original_aes_iv_b64)
        print("Ciphertext (of message)  :", original_aes_ciphertext_b64)
        print("--------------------------------------------------")


    except Exception as e:
        print(f"\nAn error occurred during Kyber key encapsulation: {e}")
        # Clean up sys.path before exiting
        if src_dir in sys.path:
             sys.path.remove(src_dir)
        exit() # Exit if Kyber process fails


    finally:
        # Clean up sys.path by removing the added directory after the script finishes
        if src_dir in sys.path:
             sys.path.remove(src_dir)


# Run the main function when the script is executed
if __name__ == "__main__":
    main()
