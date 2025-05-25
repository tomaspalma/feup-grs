from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from cryptography.hazmat.primitives import hashes

import requests
import os
import socket
import threading

load_dotenv()

circuits = dict()

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

    return (public_pem, private_pem, public_key, private_key)

(public_pem, private_pem, public_key, private_key) = generate_keypair()

def handle_new_circuit(circuit_id, left, right):
    print("RIGHT: ", right, flush=True)
    print("LEFT: ", left, flush=True)

    circuits[circuit_id] = {
        "left": left,
        "right": right
    }

    print("CIRCUITS: ", circuits, flush=True)

def handle_client_pkey(circuit_id, public_key):
    client_public_key = load_pem_public_key(public_key.encode())

    shared_secret = private_key.exchange(
        ec.ECDH(),
        client_public_key
    )

    print("ONION SHARED SECRET: ", shared_secret, flush=True)

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=None,  # Optional salt
        info=b""
    ).derive(shared_secret)

    print("SHARED KEY: ", key, flush=True)

    if circuits.get(circuit_id):
        circuits[circuit_id]["secret"] = key
    else:
        print("No circuit found for ", circuit_id, flush=True)

def handle_data(circuit_id, data):
    if circuits.get(circuit_id):
        print("HANDLING DATA BEFORE DECRYPT: ", data, flush=True)
        key = circuits[circuit_id]["secret"]

        # 1. Decrypt data
        cipher = Cipher(algorithms.AES(key), modes.CTR(b"\x8f\x07@nq}F\x1e\x1cv\x95\x13,\xb3\xef\xe9"), backend=default_backend())
        decryptor = cipher.decryptor()

        data = decryptor.update(data.encode()) + decryptor.finalize()

        print("HANDLING DATA AFTER DECRYPT: ", data, flush=True)

        # 2. Send it to node on the right
        if circuits[circuit_id]["right"] != "None":
            print("NÃO DEVIA TER VINDO PARA AQUI?")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((circuits[circuit_id]["right"], 9000))

            sock.sendall(data)
        else:
            res = requests.get(data)

# 1. Make request to controller
while True:
    try: 
        res = requests.post(f"{os.getenv('CONTROLLER_URL')}/identities", json={
            'address': os.getenv('ADDRESS'),
            'port': os.getenv('PORT'),
            'public_key': public_pem.decode('utf-8'),
        })

        if res.ok:
            print("Identity registered successfully.")
            break

    except Exception as e:
        print("Error: ", e)

def handle_connection(conn):
    with conn:
        while True:
            data = conn.recv(1024)

            msg = data.decode()
            if msg != "":
                print("RECEIVED: ", msg, flush=True)

                if msg.startswith("client_pkey"):
                    circuit_id = msg.split(",")[1]
                    public_key = msg.split(",")[2]

                    handle_client_pkey(circuit_id, public_key)
                elif msg.startswith("controller_setup"):
                    circuit_id = msg.split(",")[1]
                    left = msg.split(",")[2]
                    right = msg.split(",")[3]

                    handle_new_circuit(circuit_id, left, right)
                elif msg.startswith("data"):
                    circuit_id = msg.split(",")[1]
                    data = msg.split(",")[2]                    
                    handle_data(circuit_id, data)

# 2. Listen for requests
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((os.getenv('HOST'), int(os.getenv('PORT'))))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_connection, args=(conn,)).start()
            
                   
except Exception as e:
    print("Error: ", e, flush=True)