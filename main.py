import socket               # Import socket module

s = socket.socket()         # Create a socket object
host = "pets.ewi.utwente.nl" # Get local machine name
port = 53132                # Reserve a port for your service.

s.connect((host, port))
print(s.recv(1024))
s.close()                     # Close the socket when done