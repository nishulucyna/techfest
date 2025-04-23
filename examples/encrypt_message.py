import sys
import os
import base64

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.join(current_dir, os.pardir) 
src_dir = os.path.join(parent_dir, 'src')      

sys.path.insert(0, src_dir)

try:

    from aes_handler import encrypt_aes256_cbc
except ImportError:
    print(f"Error: Could not import the 'encrypt_aes256_cbc' function from '{src_dir}/aes_handler.py'.")
    print("Please ensure 'aes_handler.py' exists in that directory.")
    
    if src_dir in sys.path:
         sys.path.remove(src_dir)
    exit() 


try:
    from kyber_handler import perform_kyber_encapsulation
except ImportError:
    print(f"Error: Could not import the 'perform_kyber_encapsulation' function from '{src_dir}/kyber_handler.py'.")
    print("Please ensure 'kyber_handler.py' exists in that directory and contains the function.")
    
    if src_dir in sys.path:
         sys.path.remove(src_dir)
    exit() 

def main():
    """
    Performs AES encryption on a user message and then performs Kyber key
    encapsulation using the handler function. Outputs the results of both steps.
    """
    print("--- AES Encryption and Kyber Key Encapsulation ---")

    
    print("\nPerforming initial AES encryption on user message...")

    message_to_encrypt = input("Enter the message to encrypt with AES: ")

    try:
        
        aes_encryption_result = encrypt_aes256_cbc(message_to_encrypt)

       
        original_aes_key_b64 = aes_encryption_result["key"]
        original_aes_iv_b64 = aes_encryption_result["iv"]
        original_aes_ciphertext_b64 = aes_encryption_result["ciphertext"]

        print("\nInitial AES Encryption Successful!")
        print("AES Key (for message)    :", original_aes_key_b64)
        print("AES IV (for message)     :", original_aes_iv_b64)
        print("Ciphertext (of message)  :", original_aes_ciphertext_b64)

    except Exception as e:
        print(f"\nAn error occurred during initial AES encryption: {e}")
       
        if src_dir in sys.path:
             sys.path.remove(src_dir)
        exit() 

    print("\nPerforming Kyber Key Encapsulation...")

    kemalg = "ML-KEM-512" 
    try:
       
        kyber_results = perform_kyber_encapsulation(kemalg)

        kyber_client_secret_key_b64 = kyber_results["client_secret_key"]
        kyber_ciphertext_b64 = kyber_results["ciphertext"]
      
        kyber_shared_secret_b64 = kyber_results["shared_secret"]

        print("Kyber Key Encapsulation Successful!")
        print("\n--- Information for Decryption Program ---")
        print("Kyber Client Secret Key (Base64) :", kyber_client_secret_key_b64)
        print() 
        print("Kyber Ciphertext (Base64)        :", kyber_ciphertext_b64)
        print() 
        print("Kyber Shared Secret (Client-Derived) (Base64):", kyber_shared_secret_b64)
        print("------------------------------------------")

       
        print("\n--- Information for Decryption Program (cont.) ---")
        print("AES Key (for message)    :", original_aes_key_b64) 
        print("AES IV (for message)     :", original_aes_iv_b64)
        print("Ciphertext (of message)  :", original_aes_ciphertext_b64)
        print("--------------------------------------------------")


    except Exception as e:
        print(f"\nAn error occurred during Kyber key encapsulation: {e}")
       
        if src_dir in sys.path:
             sys.path.remove(src_dir)
        exit()


    finally:
       
        if src_dir in sys.path:
             sys.path.remove(src_dir)



if __name__ == "__main__":
    main()
