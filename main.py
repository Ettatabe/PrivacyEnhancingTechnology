import socket               # Import socket module)
import os
import crypto
from Crypto.PublicKey import RSA


mixnet1_pubkey = RSA.importKey(open('public-key-mix-1.pem').read())
mixnet2_pubkey = RSA.importKey(open('public-key-mix-2.pem').read())
mixnet3_pubkey = RSA.importKey(open('public-key-mix-3.pem').read())

def unsigned(n):
    return n & 0xFFFFFFFF

def create_payload(recipient, message):
    full_string = recipient + ',' + message
    payload = bytearray()
    payload.extend(bytes(full_string, 'ascii'))

    return payload

def construct_onion_layer(pubkey, iv1, key1, iv2, key2, payload):
    padded_payload = crypto.pkcs7_pad(bytes(payload))
    aes_encryption = crypto.aes_encrypt(iv2, key2, padded_payload)
    rsa_encryption = crypto.rsa_pkcs1_oaep_encrypt(pubkey, iv1 + key1)
    E = rsa_encryption + aes_encryption

    return E

s = socket.socket()
host = "pets.ewi.utwente.nl"
port = 52192

'''Generate random IVs and Keys'''
IV1 = crypto.generate_IV(16)
IV2 = crypto.generate_IV(16)
IV3 = crypto.generate_IV(16)
key1 = crypto.generate_Key(16)
key2 = crypto.generate_Key(16)
key3 = crypto.generate_Key(16)

message = "Hey"
'''Make the actual message'''
payload = create_payload('Alice', message)

'''Construct the onion layers'''
E1 = construct_onion_layer(mixnet3_pubkey, IV3, key3, IV1, key1, payload)
E2 = construct_onion_layer(mixnet2_pubkey, IV2, key2, IV2, key2, E1)
E3 = construct_onion_layer(mixnet1_pubkey, IV1, key1, IV1, key1, E2)

final_msg = bytearray(len(E3).to_bytes(4, byteorder='big', signed=False) + E3)

s.connect((host, port))
s.send(final_msg)

print(s.recv(1024))

s.close()                     # Close the socket when done


