import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

HOST = "127.0.0.1"
PORT = 6000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Server listening...")
conn, addr = server.accept()
print("Connected:", addr)

# Send public key
conn.send(public_pem)

# Receive encrypted AES key
encrypted_aes = conn.recv(256)
aes_key = private_key.decrypt(
    encrypted_aes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

cipher = Fernet(aes_key)

# Receive encrypted message
encrypted_msg = conn.recv(1024)
msg = cipher.decrypt(encrypted_msg)

print("Client says:", msg.decode())

reply = cipher.encrypt(b"Secure message received")
conn.send(reply)

conn.close()
server.close()