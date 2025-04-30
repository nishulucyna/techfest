import oqs
import logging

# Set up logging to display minimal output
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def perform_kyber_encapsulation(kemalg: str = "ML-KEM-1024"):
    logger.info("\n--- Kyber Key Exchange ---")
    
    with oqs.KeyEncapsulation(kemalg) as client, oqs.KeyEncapsulation(kemalg) as server:
        public_key = client.generate_keypair()

        ciphertext, shared_secret_server = server.encap_secret(public_key)

        shared_secret_client = client.decap_secret(ciphertext)

        if shared_secret_client != shared_secret_server:
            raise ValueError("Shared secrets mismatch!")
        
        logger.info("Shared secrets coincide: True")

        return {
            "client_secret_key": client.export_secret_key(),
            "ciphertext": ciphertext,
            "shared_secret": shared_secret_client
        }

def perform_kyber_decapsulation(ciphertext, client_secret_key, kemalg: str = "ML-KEM-1024"):
    logger.info("\n--- Kyber Decapsulation ---")

    with oqs.KeyEncapsulation(kemalg) as client:
        shared_secret = client.decap_secret(ciphertext)

        logger.info("Decapsulation successful, shared secret recovered.")
        return shared_secret