from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

with open("public-key-mix-1.pem", "rb") as key_file:
    public_key_mix_1 = serialization.load_der_public_key(key_file.read(), backend=default_backend())

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def aes_encrypt(iv, key, message):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()

    return cipher_text

def aes_decrypt(iv, key, message):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(message) + decryptor.finalize()

    return plain_text