# aes_handler.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class AESHandler:
    def __init__(self):
        self.backend = default_backend()

    def encrypt(self, plaintext, key, associated_data=None):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes for AES-128, 192, or 256.")

        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag  # Get the tag. GCM includes the tag in the output
        logger.info(f"AES Ciphertext (hex): {ciphertext.hex()}")
        logger.info(f"AES IV (hex): {iv.hex()}")
        logger.info(f"AES Tag (hex): {tag.hex()}")  # Log the tag
        return ciphertext, iv, tag # Return ciphertext, IV, and tag

    def decrypt(self, ciphertext, iv, key, associated_data=None, tag=None):
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes long for GCM.")
        if tag is None:
            raise ValueError("Authentication tag must be provided for GCM decryption")
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend) # Use the provided tag
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext