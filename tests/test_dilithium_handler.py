import logging
import base64
import oqs
from pprint import pformat

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Stream handler to output log messages
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())

logger.info("liboqs version: %s", oqs.oqs_version())
logger.info("liboqs-python version: %s", oqs.oqs_python_version())
logger.info(
    "Enabled signature mechanisms:\n%s",
    pformat(oqs.get_enabled_sig_mechanisms(), compact=True),
)

def perform_dilithium_signing(message: bytes, sigalg: str = "ML-DSA-44"):
    """
    Perform digital signature generation using the Dilithium algorithm.

    Args:
        message (bytes): The message to sign.
        sigalg (str): The signature algorithm to use (default is "ML-DSA-44").

    Returns:
        dict: A dictionary containing the base64 encoded public key, signature.
    Raises:
        Exception: If any error occurs during the signing process.
    """
    logger.info("\n--- Dilithium Signing Process ---")
    
    try:
        # Create signer and verifier with the given signature algorithm
        with oqs.Signature(sigalg) as signer, oqs.Signature(sigalg) as verifier:
            logger.info("Signature details:\n%s", pformat(signer.details))

            # Generate keypair
            signer_public_key = signer.generate_keypair()
            logger.info(f"Generated keypair for algorithm {sigalg}:")
            logger.info(f"Public Key: {base64.b64encode(signer_public_key).decode('utf-8')}")

            # Sign the message
            signature = signer.sign(message)
            logger.info("Message signed successfully.")

            # Return the results in a dictionary, encoded in base64
            return {
                "public_key": base64.b64encode(signer_public_key).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8')
            }

    except Exception as e:
        logger.error(f"An error occurred during Dilithium signing: {e}")
        raise


def perform_dilithium_verification(message: bytes, signature: bytes, public_key: bytes, sigalg: str = "ML-DSA-44"):
    """
    Verifies the signature of a message using the Dilithium algorithm.

    Args:
        message (bytes): The message whose signature is to be verified.
        signature (bytes): The signature to verify.
        public_key (bytes): The public key to verify the signature against.
        sigalg (str): The signature algorithm to use (default is "ML-DSA-44").

    Returns:
        bool: True if the signature is valid, False otherwise.
    Raises:
        Exception: If any error occurs during the verification process.
    """
    logger.info("\n--- Dilithium Signature Verification Process ---")
    
    try:
        # Create a verifier with the given signature algorithm
        with oqs.Signature(sigalg) as verifier:
            # Verify the signature
            is_valid = verifier.verify(message, signature, public_key)
            logger.info(f"Signature valid? {is_valid}")

            return is_valid

    except Exception as e:
        logger.error(f"An error occurred during Dilithium signature verification: {e}")
        raise


# For direct testing of the module
if __name__ == "__main__":
    print("Running dilithium_handler.py directly (for testing)...")
    try:
        test_message = b"This is the message to sign"
        
        # Sign the message
        signing_results = perform_dilithium_signing(test_message)
        print("\n--- Dilithium Signature Test Output ---")
        print("Public Key (Base64):", signing_results["public_key"])
        print("Signature (Base64):", signing_results["signature"])

        # Verify the signature
        signature = base64.b64decode(signing_results["signature"])
        public_key = base64.b64decode(signing_results["public_key"])
        verification_result = perform_dilithium_verification(test_message, signature, public_key)
        print("Signature Verified?:", verification_result)

    except Exception as e:
        print(f"Error during direct run: {e}")