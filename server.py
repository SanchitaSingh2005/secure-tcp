import socket
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import os

HOST = '127.0.0.1'
PORT = 12345

key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    # Send RSA public key
    conn.send(public_key.export_key())

    # Receive AES session key
    encrypted_session_key = conn.recv(256)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    while True:
        try:
            # Receive command first (text or file)
            command = conn.recv(1024)
            if not command:
                break
            command = AES.new(session_key, AES.MODE_EAX, nonce=command[:16]).decrypt_and_verify(command[16:], command[16:32])
            command = command.decode()

            if command.startswith("SEND "):
                filename = command.split(" ")[1]
                # Receive file size
                filesize = int(conn.recv(16).decode())
                with open(f"received_{filename}", "wb") as f:
                    remaining = filesize
                    while remaining:
                        chunk = conn.recv(min(1024, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                print(f"[{addr}] File received: {filename}")
            else:
                # normal text message
                nonce = conn.recv(16)
                tag = conn.recv(16)
                ciphertext = conn.recv(1024)
                if not ciphertext:
                    break
                data = AES.new(session_key, AES.MODE_EAX, nonce=nonce).decrypt_and_verify(ciphertext, tag)
                print(f"[{addr}] {data.decode()}")
        except Exception as e:
            print(f"[{addr}] disconnected.")
            break

    conn.close()
