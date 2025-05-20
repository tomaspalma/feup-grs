from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import argparse
import requests
import base64
import os

load_dotenv()

def encrypt(msg: bytes, public_keys: list):
    key1 = serialization.load_pem_public_key(public_keys[0].encode(), backend=default_backend())

    cipher1 = key1.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("cipher1: ", cipher1)

    key2 = serialization.load_pem_public_key(public_keys[1].encode(), backend=default_backend())

    cipher1base64 = base64.b64encode(cipher1)

    cipher2 = key2.encrypt(
        cipher1base64,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # for key in public_keys:
    #     public_key = serialization.load_pem_public_key(key.encode(), backend=default_backend())

    #     msg = public_key.encrypt(
    #         msg,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )

    #     msg = base64.b64encode(msg)

    return msg

def main():
    parser = argparse.ArgumentParser(description="GRS Onion Client")
    
    parser.add_argument("url", help="URL of the website")

    args = parser.parse_args()

    # 1. Get circuit entry
    res = requests.post(f"{os.getenv('CONTROLLER_URL')}/circuit")
    
    msg = encrypt(args.url.encode(), res.json()['keys'])

if __name__ == "__main__":
    main()
