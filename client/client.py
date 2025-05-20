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

pem_data = b'''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq7I+z5VdOFakmxQBhrzJ
wFb9tkTZXvYFOOn8D8H/z42hXspiZWvIM/6UMUko2O4UQw7yqayRIWfFQyq4g4Zp
VAeRF/3aO2vEOhI0FAOiFMkevZdQarGPlisNMwwzJ8UDtm++fPhX7EzmDwDW4dVw
haJ/a7QB2PWmhm4M46n/tdNSbczU5tE8B15h1oQ5fURmGta5dd+cmgosc9/PR5mT
TNG+cdZ80QvtKQEEI1R/9cRGw3DPE1riuuNj6/fenBcCh51//Y0j37sgq9aC1/KH
2t/BQK2pVfoVFJOYpGrNQhIdo0iLtRgd57sUoEATjvzkaZVH0mgNG/uIyfCbYlkW
DwIDAQAB
-----END PUBLIC KEY-----'''

def encrypt(msg: bytes, public_keys: list):
    for key in public_keys:
        print("KEY: ", key.encode())

        public_key = serialization.load_pem_public_key(key.encode(), backend=default_backend())

        msg = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    return msg

def main():
    parser = argparse.ArgumentParser(description="GRS Onion Client")
    
    parser.add_argument("url", help="URL of the website")

    args = parser.parse_args()

    # 1. Get circuit entry
    res = requests.post(f"{os.getenv('CONTROLLER_URL')}/circuit")
    
    print("RES: ", res.json())
    
    msg = encrypt(args.url.encode(), res.json()['keys'])

    print("MESSAGE: ", msg)    

if __name__ == "__main__":
    main()
