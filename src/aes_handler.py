from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    # Use cryptography's HKDF for key derivation
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"",
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def encrypt_aes256_gcm(message: str, key: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}

def decrypt_aes256_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')