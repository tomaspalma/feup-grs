from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime

import random
import os
import socket

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

db = SQLAlchemy(app)

class Identity(db.Model):
    __tablename__ = 'identities'
    __table_args__ = {'schema': 'onion_controller'} 

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    port = db.Column(db.String(255), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/identities', methods=['POST'])
def identities():
    json = request.get_json()

    id = json['id']
    public_key = json['public_key']
    address = json['address']
    port = json['port']

    existing_identity = Identity.query.filter_by(name=id).first()
    if existing_identity:
        existing_identity.public_key = public_key
        existing_identity.address = address
        existing_identity.port = port
        existing_identity.last_updated = datetime.utcnow()

        db.session.commit()
    else:
        identity = Identity(
            name=id,
            public_key=public_key,
            address=address,
            port=port,
            last_updated=datetime.utcnow()
        )

        db.session.add(identity)
        db.session.commit()

    return json

@app.route("/circuit", methods=['POST'])
def circuit():
    #json = request.get_json()

    # get identities from database
    identities = Identity.query.all()

    # 1. Select nodes
    selected_nodes = []
    alive_nodes = 0

    while alive_nodes < 3:
        selected_nodes.append(random.choice(identities))

        alive_nodes += 1

    # 2. Send circuit information to nodes
    for i in range(len(selected_nodes)):
        node = selected_nodes[i]

        while True:
            try: 
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((node.address, int(node.port)))
                break
            except Exception as e:
                print("Error: ", e)
                continue

        right = "None" if i == len(selected_nodes)-1 else selected_nodes[i+1].public_key
        left = "None" if i == 0 else selected_nodes[i-1].public_key

        message = f"{left},{right}".encode()
        sock.sendall(message)


    # 3. Return circuit entry to client
    return {
        "entry": selected_nodes[0].address,
        "keys": list(map(lambda x: x.public_key , selected_nodes))
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True) 
