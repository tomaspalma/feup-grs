from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import argparse
import requests
import base64
import socket
import os

load_dotenv()

def encrypt_layer(msg: bytes, key):
    encoded_key = load_pem_public_key(key.encode('utf-8'))

    ephemeral_private = ec.generate_private_key(encoded_key.curve)
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(ec.ECDH(), encoded_key)

    # Derive AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'layered_encryption',
    ).derive(shared_secret)

    # Encrypt payload with AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(msg) + encryptor.finalize()
    
    # Pack data: ephemeral public key + IV + ciphertext
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return ephemeral_public_bytes + iv + ciphertext
    
def main():
    parser = argparse.ArgumentParser(description="GRS Onion Client")
    
    parser.add_argument("url", help="URL of the website")

    args = parser.parse_args()

    client_private_key = ec.generate_private_key(ec.SECP256R1())
    client_public_key = client_private_key.public_key()

    # 1. Get circuit entry
    res = requests.post(f"{os.getenv('CONTROLLER_URL')}/circuit")

    print("MEU: ", flush=True)

    msg = args.url.encode()
    json = res.json()
    for key in json['keys']:
        msg = encrypt_layer(msg, key)

    print("CIRCUIT: ", json['circuit'], flush=True)

    # 2. Send client public key
    for node in json['circuit']:
        while True:
            try: 
                public_pem = client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                print("ADDRESS: "   , node["address"])

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((node["address"], int(node["port"])))
                
                # Send the message
                sock.sendall(public_pem)

                break
            except Exception as e:
                print("Error: ", e, flush=True)
                continue
        
    
if __name__ == "__main__":
    main()
