from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import argparse
import requests
import base64
import socket
import os

load_dotenv()

client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

def encrypt_layer(msg: bytes, key, decrypt=False):
    onion_encoded_key = load_pem_public_key(key.encode('utf-8'))

    shared_secret = client_private_key.exchange(ec.ECDH(), onion_encoded_key)

    # Derive AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b""
    ).derive(shared_secret)

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(b"\x8f\x07@nq}F\x1e\x1cv\x95\x13,\xb3\xef\xe9"), backend=default_backend())
    if decrypt:
        decryptor = cipher.decryptor()
        return decryptor.update(msg) + decryptor.finalize()
    else:
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

    # 2. Send client public key
    public_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((json["circuit"][0]["address"], int(json["circuit"][0]["port"])))

        # Send client public key
        msg = f"client_pkey,{json['id']},{public_pem.decode()},END"
        sock.sendall(msg.encode())

        # Send encrypted URL data
        msg = f"data,{json['id']},{base64.b64encode(url).decode()},END"
        sock.sendall(msg.encode())

        # Wait for the response on the same socket
        data = b""
        while b",END" not in data:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk

        message = data.decode()
        message = message.split(",")[2].encode()
        message = base64.b64decode(message)

        for key in json['keys'][::-1]:
            message = encrypt_layer(message, key, decrypt=True)

        print("Response: ", message, flush=True)

    except Exception as e:
        print("Error: ", e, flush=True)
        return
    finally:
        sock.close()

    
if __name__ == "__main__":
    main()
