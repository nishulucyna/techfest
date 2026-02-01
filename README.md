# QRYPTEX

A quantum-resistant hybrid encryption model combining AES and Kyber, with digital signature implementation using Dilithium

## Step 1: AES encryption of the plaintext
The plaintext is encrypted using AES first and the ciphertext along with the AES key is passed to the next step.
AES-256 is used for plaintext encryption due to its fast processing capabilities and strong security against classical cryptanalysis. While not immune to all potential quantum attacks, its large key size provides a level of defense against certain quantum threats.

## Step 2: Encryption of the AES key using Kyber
AES, being a symmetric algorithm, requires shared keys, and common key exchange methods like Diffie-Hellman, RSA, and elliptic curves are susceptible to Shor's algorithm. We have implemented Kyber as a quantum-resistant alternative for secure key exchange.
The recipient generates a Kyber public/private key pair and sends the public key to the sender. The sender uses this public key in a Kyber encapsulation process to generate a unique shared secret and a Kyber ciphertext. A symmetric AES key is then derived from this shared secret using a Key Derivation Function (like HKDF), and a new, random IV is generated. This derived key and new IV are used in a second AES encryption step to encrypt the original AES key (which was used for the initial message encryption). Finally, the Kyber ciphertext, the encrypted original AES key ciphertext, the IV for the second AES encryption, and the IV for the original message encryption are sent to the receiver, who uses their Kyber private key and the Kyber ciphertext to recover the shared secret and reverse the process.

## Step 3: Digital Signature Implementation
Dilithium provides authentication of the sender and ensures the integrity of the message. This guarantees that the message truly came from the claimed sender and hasn't been modified in transit. SHA-3 is used for hashing which isn’t affected by Grover’s algorithm to the extent it becomes vulnerable to brute-force attack.
The IV, encrypted message and the encrypted key are packaged together. Next, the sender uses their private digital key to create a unique signature for this entire package. This signature confirms that the sender sent it and that the contents haven't been tampered with.

## Step 4: Transmission, Verification and Decryption
The Kyber Ciphertext (which gives shared secret on decryption with Kyber private key), IV for key encryption, Ciphertext of original AES key, AES IV, Ciphertext of message and the Digital signature is bundled and sent to the receiver. 

Upon receipt, the receiver extracts this data and first verifies the Dilithium signature using the sender's public key; if invalid, the process stops. If valid, the receiver uses their private Kyber key to retrieve the AES key.

 Finally, the receiver uses this recovered AES key and the received IV to decrypt the AES ciphertext.
A quantum-resistant hybrid cryptographic model combining AES and Kyber, with digital signature implementation using Dilithium.
