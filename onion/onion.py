from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import requests
import os
import socket

load_dotenv()

def generate_keypair():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # You can use 4096 for stronger security
    )

    # Get public key from private key
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Use a password-based algorithm for more security
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (public_pem, private_pem)

(public_pem, private_pem) = generate_keypair()

# 1. Make request to controller
while True:
    try: 
        res = requests.post(f"{os.getenv('CONTROLLER_URL')}/identities", json={
            'id': os.getenv('REPLICA_NAME'),
            'public_key': public_pem.decode('utf-8'),
            'address': os.getenv('ADDRESS'),
            'port': os.getenv('PORT')
        })

        if res.ok:
            print("Response OK")
            break
    except Exception as e:
        print("Error: ", e)

# 2. Listen for requests
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((os.getenv('HOST'), int(os.getenv('PORT'))))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)