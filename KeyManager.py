import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class KeyManager:
    """This class manages key encryption and decryption as well as generation of keys"""

    def __init__(self):
        """Initializes with private and public key"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def getPublicKey(self):
        """Returns encoded public key for distribution over the network"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1)

    def readPublicKey(self, encoded):
        """Reads and returns the public key"""
        return serialization.load_pem_public_key(encoded, backend=default_backend())

    def encodeKey(self, key):
        """Encodes passed key"""
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1)

    def encryptUsingPublicKey(self, message):
        """Encrypts using public key"""
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def signUsingPrivateKey(self, message):
        """Encrypts using private key"""
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def decryptUsingPrivateKey(self, encrypted):
        """Decrypts using private key"""
        return self.private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def verifyUsingPublicKey(self, signature, message, key):
        """Decrypts using public key"""
        try:
            key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

    def encrypt(self, message, key):
        """Encrypts message using passed key"""
        encrypted = key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        return encrypted