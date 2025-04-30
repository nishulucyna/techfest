# kyber_handler.py
import logging
import os
from pprint import pformat

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import oqs

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

KEM_ALGORITHM = "ML-KEM-1024"
SALT_LENGTH = 32
INFO = b'aes-key'
KEY_LENGTH = 32

def generate_key_pair():
    """Generates a Kyber key pair."""
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.secret_key
            logger.info("Kyber Key Pair generated.")
            logger.info(f"Public Key (hex): {bytes(public_key).hex()}")
            logger.info(f"Private Key (hex): {bytes(private_key).hex()}")
            return public_key, private_key
    except oqs.MechanismNotEnabledError:
        logger.error(f"ERROR: The KEM algorithm '{KEM_ALGORITHM}' is not enabled.")
        raise
    except Exception as e:
        logger.error(f"An error occurred during key pair generation: {e}")
        raise

def encapsulate_kem(public_key):
    """Encapsulates a shared secret using the recipient's public key."""
    salt = os.urandom(SALT_LENGTH)
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            derived_aes_key = derive_aes_key(shared_secret, salt)
            logger.info("Kyber encapsulation performed.")
            logger.info(f"Ciphertext (hex): {ciphertext.hex()}")
            logger.info(f"Shared Secret (hex): {shared_secret.hex()}")
            logger.info(f"Salt (hex): {salt.hex()}")
            logger.info(f"Derived AES Key (hex): {derived_aes_key.hex()}")
            return derived_aes_key, salt, ciphertext
    except oqs.MechanismNotEnabledError:
        logger.error(f"ERROR: The KEM algorithm '{KEM_ALGORITHM}' is not enabled.")
        raise
    except Exception as e:
        logger.error(f"An error occurred during key encapsulation: {e}")
        raise

def decapsulate_kem(ciphertext, private_key):
    """Decapsulates the shared secret using the private key and ciphertext."""
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, bytes(private_key)) as kem: # Convert private_key to bytes
            shared_secret = kem.decap_secret(ciphertext)
            logger.info("Kyber decapsulation performed.")
            logger.info(f"Shared Secret (hex): {shared_secret.hex()}")
            return shared_secret
    except oqs.MechanismNotEnabledError:
        logger.error(f"ERROR: The KEM algorithm '{KEM_ALGORITHM}' is not enabled.")
        raise
    except Exception as e:
        logger.error(f"An error occurred during key decapsulation: {e}")
        raise

def derive_aes_key(shared_secret, salt):
    """Derives an AES key from the shared secret and salt using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=INFO,
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_secret)
    return derived_key

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    try:
        # Example of key generation
        public_key, private_key = generate_key_pair()
        print(f"\nPublic Key for Encapsulation: {bytes(public_key).hex()}")

        # Example of encapsulation
        if public_key:
            derived_key, salt_output, kyber_ct = encapsulate_kem(public_key)
            print(f"\nDerived AES Key (Encapsulation): {derived_key.hex()}")
            print(f"Salt: {salt_output.hex()}")
            print(f"Kyber Ciphertext: {kyber_ct.hex()}")

            # Example of decapsulation
            if kyber_ct and private_key:
                decapsulated_secret = decapsulate_kem(kyber_ct, private_key)
                derived_key_decapsulation = derive_aes_key(decapsulated_secret, salt_output)
                print(f"\nDecapsulated Shared Secret: {decapsulated_secret.hex()}")
                print(f"Derived AES Key (Decapsulation): {derived_key_decapsulation.hex()}")
                print(f"Shared secrets match: {derived_key == derived_key_decapsulation}")

    except oqs.MechanismNotEnabledError as e:
        logger.error(e)
    except Exception as e:
        logger.error(f"An error occurred: {e}")