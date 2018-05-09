import socket               # Import socket module)
import os
import crypto

def unsigned(n):
    return n & 0xFFFFFFFF

def create_payload(recipient, message):
    full_string = recipient + ',' + message
    payload = bytearray()
    payload.extend(len(full_string).to_bytes(4, byteorder='big', signed=False)) # Four bytes to describe the length of message
    payload.extend(bytes(full_string, 'ascii'))

    return payload

def construct_msg(recipient, msg):
    payload = create_payload(recipient, msg)


s = socket.socket()
host = "pets.ewi.utwente.nl"
port = 55146

message = 'hey'

payload = create_payload('Alice', message)

print(payload)

s.connect((host, port))
s.send(payload)

print(s.recv(1024))

s.close()                     # Close the socket when done


