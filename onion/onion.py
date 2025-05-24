from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import requests
import os
import socket

load_dotenv()

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (public_pem, private_pem)

(public_pem, private_pem) = generate_keypair()

# 1. Make request to controller
try: 
    res = requests.post(f"{os.getenv('CONTROLLER_URL')}/identities", json={
        'address': os.getenv('ADDRESS'),
        'port': os.getenv('PORT'),
        'public_key': public_pem.decode('utf-8'),
    })

except Exception as e:
    print("Error: ", e)

# 2. Listen for requests
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("HOST: ", os.getenv('HOST'))
        print("PORT: ", os.getenv('PORT'))
        s.bind((os.getenv('HOST'), int(os.getenv('PORT'))))
        s.listen()
        print("LISTENING: ", flush=True)
        while True:
            conn, addr = s.accept()
            print("After accept")
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break

except Exception as e:
    print("Error: ", e, flush=True)