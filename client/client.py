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

client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

def encrypt_layer(msg: bytes, key):
    print("KEY: ", key, flush=True)
    onion_encoded_key = load_pem_public_key(key.encode('utf-8'))

    shared_secret = client_private_key.exchange(ec.ECDH(), onion_encoded_key)

    print("CLIENT SHARED SECRET: ", shared_secret, flush=True)

    # Derive AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b""
    ).derive(shared_secret)

    print("CLIENT AES KEY: ", aes_key, flush=True)

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(b"\x8f\x07@nq}F\x1e\x1cv\x95\x13,\xb3\xef\xe9"), backend=default_backend())
    encryptor = cipher.encryptor()

    return encryptor.update(msg) + encryptor.finalize()
    
def main():
    parser = argparse.ArgumentParser(description="GRS Onion Client")
    
    parser.add_argument("url", help="URL of the website")

    args = parser.parse_args()

    # 1. Get circuit entry
    res = requests.post(f"{os.getenv('CONTROLLER_URL')}/circuit")

    url = args.url.encode()
    json = res.json()
    for key in json['keys']:
        url = encrypt_layer(url, key)

    print("CIRCUIT: ", json["circuit"], flush=True)
    # 2. Send client public key
    for i, node in enumerate(json['circuit']):
        while True:
            print("Sending to ", node, flush=True)
            try: 
                public_pem = client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((node["address"], int(node["port"])))

                msg = f"client_pkey,{json['id']},{public_pem.decode()},END" 
                sock.sendall(msg.encode())

                break
            except Exception as e:
                print("Error: ", e, flush=True)
                continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((json['circuit'][0]["address"], int(json['circuit'][0]["port"])))

    msg = f"data,{json['id']},{url},END" 
    sock.sendall(msg.encode())
    
if __name__ == "__main__":
    main()
