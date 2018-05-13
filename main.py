import socket               # Import socket module)
import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import urllib.request as urllib
import time

'''This is our public rsa key'''
with open("rsa_public_key.pem", "rb") as key_file:
    my_pubkey = serialization.load_pem_public_key(
         key_file.read(),
         backend=default_backend()
     )

'''Our private rsa key'''
with open("rsa_private_key.pem", "rb") as key_file:
    my_privkey = serialization.load_pem_private_key(
        key_file.read(),
        password=bytes('password', 'ascii'),
        backend=default_backend()
    )

with open("public-key-mix-1.pem", "rb") as key_file:
    mixnet1_pubkey = serialization.load_pem_public_key(
         key_file.read(),
         backend=default_backend()
     )

with open("public-key-mix-2.pem", "rb") as key_file:
    mixnet2_pubkey = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

with open("public-key-mix-3.pem", "rb") as key_file:
    mixnet3_pubkey = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

#string = bytes("bla", 'ascii')
#print(crypto.rsa_decrypt(my_privkey, crypto.rsa_encrypt(my_pubkey, string)))

def unsigned(n):
    return n & 0xFFFFFFFF

def create_payload(recipient, message):
    full_string = recipient + ',' + message
    payload = bytearray()
    payload.extend(bytes(full_string, 'ascii'))

    return payload

def construct_onion_layer(pubkey, iv, key, payload):
    padded_payload = crypto.pkcs7_pad(bytes(payload))
    aes_encryption = crypto.aes_encrypt(iv, key, padded_payload)
    rsa_encryption = crypto.rsa_encrypt(pubkey, iv + key)
    rsa_string = str(''.join(format(x, '02x') for x in rsa_encryption))
    #print("RSA string: " + rsa_string)

    E = rsa_encryption + aes_encryption

    #print("Length E: " + str(len(E)))
    return E

s = socket.socket()
host = "pets.ewi.utwente.nl"
port = 57155
s.connect((host, port))

'''Generate random IVs and Keys'''
IV1 = crypto.generate_IV(16)
IV2 = crypto.generate_IV(16)
IV3 = crypto.generate_IV(16)
key1 = crypto.generate_Key(16)
key2 = crypto.generate_Key(16)
key3 = crypto.generate_Key(16)

def send_msgs(num):
    for i in range(0, num):
        message = str(i)

        '''Make the actual message'''
        payload = create_payload('Bob', message)

        '''Construct the onion layers'''
        E1 = construct_onion_layer(mixnet3_pubkey, IV3, key3, payload)
        E2 = construct_onion_layer(mixnet2_pubkey, IV2, key2, E1)
        E3 = construct_onion_layer(mixnet1_pubkey, IV1, key1, E2)

        final_msg = bytearray(len(E3).to_bytes(4, byteorder='big', signed=False) + E3)

        s.send(final_msg)
        #print(s.recv(1024))

amount_of_lines = -1
amount_of_msgs = 5
while amount_of_lines != amount_of_msgs:
    print(" amount of lines: " + str(amount_of_lines) + " amount of msgs: " + str(amount_of_msgs))
    send_msgs(1)
    amount_of_msgs = amount_of_msgs + 1

    time.sleep(.4)
    amount_of_lines = -1
    for line in urllib.urlopen(
            "https://pets.ewi.utwente.nl/log/24-wFioUJKDeizd3mJ2XQZuHL6N8CroxAdg56eNutkQv2s=/exit.txt"):
        amount_of_lines = amount_of_lines + 1

    if amount_of_msgs == amount_of_lines:
        print("found: " + str(amount_of_msgs))

s.close()                     # Close the socket when done



