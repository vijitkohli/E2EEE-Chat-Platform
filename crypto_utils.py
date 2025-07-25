"""
The aim of this file is 

Key Generation
Symmetric Encryption/Decryption
Encrypting the AES key with RSA
Random Nonce Generation
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_aes_key():
    """
    Generates a random 256-bit (32-byte) AES key.
    """
    return os.urandom(32)

def generate_rsa_keypair():
    """
    Generates an RSA private/public key pair.
    Returns the private key and the corresponding public key object.
    """

    # e = 65537, n = 2048
    # Both are co prime
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key

    return private_key, public_key

def encrypt_key_rsa(aes_key: bytes, public_key):
    """
    Encrypts a symmetric AES key using the recipient's RSA public key.
    Returns the encrypted AES key as bytes.
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_key_rsa(encrypted_key: bytes, private_key):
    """
    Decrypts an AES key using the recipient's RSA private key.
    Returns the original AES key as bytes.
    """
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def encrypt_message(message: str, aes_key: bytes):
    """
    Encrypts a plaintext message using AES-GCM.
    Returns (ciphertext, nonce, tag) as bytes.
    """
    # 96-bit nonce (standard for GCM)
    nonce = os.urandom(12)  
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    
    # 16 bytes
    tag = encryptor.tag 

    return ciphertext, nonce, tag

def decrypt_message(ciphertext: bytes, nonce: bytes, tag: bytes, aes_key: bytes):
    """
    Decrypts an AES-GCM encrypted message.
    Returns the original plaintext as a string.
    Raises an exception if authentication fails.
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')