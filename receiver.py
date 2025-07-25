from cryptography.hazmat.primitives import serialization
from crypto_utils import decrypt_key_rsa, decrypt_message

def load_private_key(path):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def main():
    # Load RSA private key
    private_key_path = "private_key.pem"
    private_key = load_private_key(private_key_path)

    # Read encrypted data from files
    with open("encrypted_aes_key.bin", "rb") as f:
        encrypted_aes_key = f.read()
    with open("ciphertext.bin", "rb") as f:
        ciphertext = f.read()
    with open("nonce.bin", "rb") as f:
        nonce = f.read()
    with open("tag.bin", "rb") as f:
        tag = f.read()

    # Decrypt AES key
    aes_key = decrypt_key_rsa(encrypted_aes_key, private_key)

    # Decrypt message
    plaintext = decrypt_message(ciphertext, nonce, tag, aes_key)

    print("Decrypted message:", plaintext)

if __name__ == "__main__":
    main()
