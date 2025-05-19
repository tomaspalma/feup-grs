from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import requests
import os

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
    print("ADDRESS: ", os.getenv('ADDRESS'))
    print("ID: ", os.getenv('REPLICA_NAME'))

    try: 
        res = requests.post(f"{os.getenv('CONTROLLER_URL')}/identities", json={
            'id': os.getenv('REPLICA_NAME'),
            'public_key': public_pem.decode('utf-8'),
            'address': os.getenv('ADDRESS')
        })

        if res.ok:
            print("Response OK")
            break
    except Exception as e:
        print("Error: ", e)

# 2. Listen for requests