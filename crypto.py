from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import os

def generate_IV(num_bytes):
    iv = os.urandom(num_bytes)
    return iv

def generate_Key(num_bytes):
    key = os.urandom(num_bytes)
    return key

def pkcs7_pad(message):
    padder = padding.PKCS7(128).padder()

    padded_data = padder.update(message)
    padded_data += padder.finalize()

    return padded_data

def pkcs7_unpad(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data + unpadder.finalize()

#with open("public-key-mix-1.pem", "rb") as key_file:
#    public_key_mix_1 = serialization.load_der_public_key(key_file.read(), backend=default_backend())

#with open("public-key-mix-2.pem", "rb") as key_file:
#    public_key_mix_2 = serialization.load_der_public_key(key_file.read(), backend=default_backend())

#with open("public-key-mix-3.pem", "rb") as key_file:
#    public_key_mix_3 = serialization.load_der_public_key(key_file.read(), backend=default_backend())

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

def rsa_encrypt(public_key, plain_text):
    cipher_text = public_key.encrypt(plain_text, padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()), algorithm = hashes.SHA256(), label = None))

    return cipher_text

def rsa_decrypt(private_key, cipher_text):
    plain_text = private_key.decrypt(cipher_text, padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()), algorithm = hashes.SHA256(), label = None))

    return plain_text

def aes_encrypt(iv, key, plain_text):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text) + encryptor.finalize()

    return cipher_text

def rsa_pkcs1_oaep_encrypt(plain_text):
    key = RSA.importKey(open('public-key-mix-1.pem').read())
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(plain_text)

    return cipher_text

def rsa_pkcs1_oaep_decrypt(cipher_text):
    key = RSA.importKey(open('private.pem').read())
    cipher = PKCS1_OAEP.new(key)
    plain_text = cipher.decrypt(cipher_text)

    return plain_text


def aes_decrypt(iv, key, plain_text):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(plain_text) + decryptor.finalize()

    return plain_text
