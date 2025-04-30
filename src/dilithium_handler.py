# src/dilithium_handler.py

import logging
from pprint import pformat
from sys import stdout

import oqs

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(stdout))

SIG_ALGORITHM = "ML-DSA-87" # Using ML-DSA

def generate_key_pair():
    """Generates a Dilithium key pair."""
    try:
        with oqs.Signature(SIG_ALGORITHM) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.secret_key
            private_key_bytes = bytes(private_key) # Ensure we have bytes
            logger.info("Dilithium Key Pair generated.")
            logger.info(f"Public Key (hex): {bytes(public_key).hex()}")
            logger.info(f"Private Key (hex): {private_key_bytes.hex()}")
            return public_key, private_key_bytes # Return bytes
    except oqs.MechanismNotEnabledError:
        logger.error(f"ERROR: The signature algorithm '{SIG_ALGORITHM}' is not enabled.")
        raise
    except Exception as e:
        logger.error(f"An error occurred during key pair generation: {e}")
        raise

def sign_message(message, private_key_bytes):
    """Signs a message using the provided private key bytes."""
    try:
        with oqs.Signature(SIG_ALGORITHM, private_key_bytes) as signer:
            signature = signer.sign(message)
            logger.info("Message signed.")
            logger.info(f"Signature (hex): {signature.hex()}")
            return signature
    except oqs.MechanismNotEnabledError:
        logger.error(f"ERROR: The signature algorithm '{SIG_ALGORITHM}' is not enabled.")
        raise
    except Exception as e:
        logger.error(f"An error occurred during signing: {e}")
        raise

def verify_signature(message, signature, public_key):
    """Verifies the signature of a message using the public key."""
    try:
        with oqs.Signature(SIG_ALGORITHM) as verifier:
            is_valid = verifier.verify(message, signature, public_key)
            logger.info(f"Signature verification result: {is_valid}")
            return is_valid
    except oqs.MechanismNotEnabledError:
        logger.error(f"ERROR: The signature algorithm '{SIG_ALGORITHM}' is not enabled.")
        raise
    except Exception as e:
        logger.error(f"An error occurred during verification: {e}")
        raise

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    public_key, private_key_bytes = generate_key_pair() # Get bytes
    message = b"Test message for Dilithium signature."
    signature = sign_message(message, private_key_bytes) # Pass bytes
    logger.info(f"Public Key: {public_key.hex()}")
    logger.info(f"Private Key: {private_key_bytes.hex()}")
    logger.info(f"Signature: {signature.hex()}")
    is_valid = verify_signature(message, signature, public_key)
    logger.info(f"Signature valid? {is_valid}")