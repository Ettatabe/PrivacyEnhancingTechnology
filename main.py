import socket               # Import socket module
from cryptography.hazmat.primitives.asymmetric import rsa

def unsigned(n):
    return n & 0xFFFFFFFF

s = socket.socket()         # Create a socket object
host = "pets.ewi.utwente.nl" # Get local machine name
port = 53327                # Reserve a port for your service.

message = 'hey'
message_length = len(message)

payload = bytearray()

payload.extend(message_length.to_bytes(4, byteorder='big', signed=False))
payload.extend(bytes(message, 'ascii'))

print(payload)

s.connect((host, port))
s.send(payload)
print(s.recv(1024))
s.close()                     # Close the socket when done


