import os
from cryptography.hazmat.primitives import serialization
from crypto_utils import (
    generate_aes_key,
    encrypt_key_rsa,
    encrypt_message
)

def load_public_key(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def main():
    # Load recipient's RSA public key from file
    recipient_public_key_path = "recipient_public_key.pem"
    public_key = load_public_key(recipient_public_key_path)

    # Get message from user
    message = input("Enter message to send: ")

    # Generate AES key
    aes_key = generate_aes_key()

    # Encrypt message with AES-GCM
    ciphertext, nonce, tag = encrypt_message(message, aes_key)

    # Encrypt AES key with recipient's RSA public key
    encrypted_aes_key = encrypt_key_rsa(aes_key, public_key)

    # Save encrypted outputs to files 
    with open("encrypted_aes_key.bin", "wb") as f:
        f.write(encrypted_aes_key)
    with open("ciphertext.bin", "wb") as f:
        f.write(ciphertext)
    with open("nonce.bin", "wb") as f:
        f.write(nonce)
    with open("tag.bin", "wb") as f:
        f.write(tag)

    print("Encrypted message and keys saved to files.")

if __name__ == "__main__":
    main()
