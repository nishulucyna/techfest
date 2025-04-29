# Key encapsulation Python example

import logging
from pprint import pformat
from sys import stdout

import timeit
import pandas as pd # type: ignore
import matplotlib.pyplot as plt

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import oqs

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(stdout))


# Configuration for benchmarking
kemalg = "ML-KEM-1024"
num_iterations = 100
salt_length = 32
salt = os.urandom(salt_length)
info = b'aes-key'
key_length = 32 

# Benchmarks
results = []

with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:
        logger.info("Key encapsulation details:\n%s", pformat(client.details))

        # Key-pair generation at client end
        public_key_client = client.generate_keypair()
    
        # Convert c_char_Array to bytes before calling .hex()
        public_key_hex = bytes(public_key_client).hex()
        secret_key_hex = bytes(client.secret_key).hex()

        # Keys are byte arrays, .hex() converts them to hexadecimal strings
        logger.info("Client Public Key: %s", public_key_hex)
        logger.info("Client Private Key: %s", secret_key_hex)

        # Kyber encapsulation at server end with client public key
        ciphertext, shared_secret_server = server.encap_secret(public_key_client)

        # Kyber decapsulation at client end with client private key
        shared_secret_client = client.decap_secret(ciphertext)

    logger.info(
        "Shared secretes coincide: %s",
        shared_secret_client == shared_secret_server,
    )

    # Derive AES key using HKDF
    hkdf_server = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    aes_key_server = hkdf_server.derive(shared_secret_server)

    hkdf_client = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    aes_key_client = hkdf_client.derive(shared_secret_client)

    logger.info(
        "Derived AES keys coincide: %s",
        aes_key_client == aes_key_server,
    )

    logger.info("Derived AES Key (Server): %s", aes_key_server.hex())