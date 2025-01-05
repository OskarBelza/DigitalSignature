import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Default directory for storing keys
KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)


class KeyManager:
    @staticmethod
    def generate_keys():
        """
        Generates an RSA key pair (public and private keys).
        Saves the keys to files and returns the keys.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        KeyManager.save_keys(public_key, private_key)
        return public_key, private_key

    @staticmethod
    def save_keys(public_key, private_key, public_key_path=f"{KEYS_DIR}/public_key.pem", private_key_path=f"{KEYS_DIR}/private_key.pem"):
        """
        Saves the public and private keys to files in PEM format.
        """
        # Save the private key
        with open(private_key_path, "wb") as priv_file:
            priv_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save the public key
        with open(public_key_path, "wb") as pub_file:
            pub_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    @staticmethod
    def load_private_key(private_key_path=f"{KEYS_DIR}/private_key.pem"):
        """
        Loads the private key from a file.
        Returns the loaded private key.
        """
        with open(private_key_path, "rb") as priv_file:
            return serialization.load_pem_private_key(
                priv_file.read(),
                password=None,
                backend=default_backend()
            )

    @staticmethod
    def load_public_key(public_key_path=f"{KEYS_DIR}/public_key.pem"):
        """
        Loads the public key from a file.
        Returns the loaded public key.
        """
        with open(public_key_path, "rb") as pub_file:
            return serialization.load_pem_public_key(
                pub_file.read(),
                backend=default_backend()
            )
