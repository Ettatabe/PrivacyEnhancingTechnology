import socket               # Import socket module)
import os
import crypto

def unsigned(n):
    return n & 0xFFFFFFFF

def create_payload(message):
    payload = bytearray()
    payload.extend(len(message).to_bytes(4, byteorder='big', signed=False)) # Four bytes to describe the length of message
    payload.extend(bytes(message, 'ascii'))

    return payload

def construct_msg(recipient, msg):
    payload = create_payload(msg)


s = socket.socket()
host = "pets.ewi.utwente.nl"
port = 53327

message = 'hey'

payload = create_payload(message)

s.connect((host, port))
s.send(payload)

print(s.recv(1024))

s.close()                     # Close the socket when done


