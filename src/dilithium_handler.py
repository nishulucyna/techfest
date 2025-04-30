import oqs
import logging

logger = logging.getLogger(__name__)

def sign_data(data: bytes, sigalg: str = "ML-DSA-65"):
    logger.info("\n--- Dilithium Signing ---")
    with oqs.Signature(sigalg) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        signature = signer.sign(data)
    return {
        "signature": signature,
        "public_key": public_key,
        "private_key": private_key
    }

def verify_signature(data: bytes, signature: bytes, public_key: bytes, sigalg: str = "ML-DSA-65"):
    with oqs.Signature(sigalg) as verifier:
        return verifier.verify(data, signature, public_key)