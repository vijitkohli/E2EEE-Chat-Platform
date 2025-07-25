from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_and_save_keys(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_path = f"{username}_private_key.pem"
    pub_path = f"{username}_public_key.pem"

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return priv_path, pub_path

def load_keys(username):
    priv_path = f"{username}_private_key.pem"
    pub_path = f"{username}_public_key.pem"
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        return generate_and_save_keys(username)

    from cryptography.hazmat.primitives import serialization

    with open(priv_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(pub_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key
