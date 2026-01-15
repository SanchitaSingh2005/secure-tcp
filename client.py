import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import os

HOST = '127.0.0.1'
PORT = 12345

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Receive RSA public key
public_key = RSA.import_key(client.recv(450))
cipher_rsa = PKCS1_OAEP.new(public_key)

# AES session key
session_key = get_random_bytes(16)
client.send(cipher_rsa.encrypt(session_key))

while True:
    msg = input("Enter message or 'SEND filename': ")
    if msg.lower() == 'exit':
        break

    if msg.startswith("SEND "):
        filename = msg.split(" ")[1]
        if not os.path.exists(filename):
            print("File not found!")
            continue
        filesize = os.path.getsize(filename)
        client.send(AES.new(session_key, AES.MODE_EAX).encrypt(msg.encode()))  # command encrypted
        client.send(f"{filesize:<16}".encode())  # send file size
        with open(filename, "rb") as f:
            client.sendall(f.read())
        print(f"File {filename} sent.")
    else:
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(msg.encode())
        client.send(cipher_aes.nonce)
        client.send(tag)
        client.send(ciphertext)

client.close()
