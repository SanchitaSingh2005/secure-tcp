# Secure-TCP

## Description
This project implements a **multi-client TCP server** with **hybrid RSA-AES encryption**, allowing secure text and file transfer between clients and server. RSA is used for secure key exchange, and AES is used for fast encryption of messages and files.

## Features
- Multi-client support using threading  
- Secure text messaging with AES encryption  
- Secure file transfer  
- RSA-based session key exchange  

## Technologies Used
- Python 3  
- Socket Programming (TCP)  
- RSA (asymmetric encryption)  
- AES (symmetric encryption)  
- Threading  

## How to Run
1. Open **two terminals** (or more if testing multi-client).  
2. Run the server first:
   ```bash
   python server.py
