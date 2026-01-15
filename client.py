import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

HOST = "127.0.0.1"
PORT = 6000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Receive public key
public_pem = client.recv(1024)
public_key = serialization.load_pem_public_key(public_pem)

# Generate AES key
aes_key = Fernet.generate_key()
cipher = Fernet(aes_key)

# Encrypt AES key with RSA
encrypted_aes = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

client.send(encrypted_aes)

# Send encrypted message
message = cipher.encrypt(b"Hello with hybrid encryption")
client.send(message)

# Receive reply
encrypted_reply = client.recv(1024)
reply = cipher.decrypt(encrypted_reply)

print("Server reply:", reply.decode())

client.close()