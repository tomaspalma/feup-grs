from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, timezone

import random
import os
import socket

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

db = SQLAlchemy(app)

class Identity(db.Model):
    __tablename__ = 'identities'
    __table_args__ = (
        db.PrimaryKeyConstraint('address', 'port'),
        {'schema': 'onion_controller'}
    )

    address = db.Column(db.Text, nullable=False)
    port = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

@app.route('/identities', methods=['POST'])
def identities():
    json = request.get_json()

    address = json['address']
    port = json['port']
    public_key = json['public_key']

    existing_identity = Identity.query.filter_by(address=address, port=port).first()
    if existing_identity:
        existing_identity.public_key = public_key
        existing_identity.last_updated = datetime.now(timezone.utc)

        db.session.commit()
    else:
        identity = Identity(
            address=address,
            port=port,
            public_key=public_key,
            last_updated=datetime.now(timezone.utc)
        )

        db.session.add(identity)
        db.session.commit()

    return {"status": "ok"}

def is_node_alive(node):
    try: 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((node.address, int(node.port)))
        return (True, sock)
    except:
        return (False, None)

@app.route("/circuit", methods=['POST'])
def circuit():
    identities = Identity.query.all()

    # 1. Select nodes
    selected_nodes = []
    alive_nodes = 0

    while alive_nodes < 3:
        candidate = random.choice(identities)

        (is_alive, sock) = is_node_alive(candidate)
        if is_alive:
            selected_nodes.append((candidate, sock))
            identities.remove(candidate)
            alive_nodes += 1
        else:
            db.session.delete(candidate)
            db.session.commit()

    # 2. Send circuit information to nodes
    for i in range(len(selected_nodes)):
        sock = selected_nodes[i][1]

        right = "None" if i == len(selected_nodes)-1 else selected_nodes[i+1][0].public_key
        left = "None" if i == 0 else selected_nodes[i-1][0].public_key
    
        message = f"{left},{right}".encode()
        try:
            sock.sendall(message)
        except Exception as e:
            print("Error sending message: ", e, flush=True)
            continue
    
        print("Message sent: ", message, flush=True)

    # 3. Return circuit entry to client
    return {
        "circuit": list(map(lambda x: { "address": x[0].address, "port": x[0].port }, selected_nodes)),
        "keys": list(map(lambda x: x[0].public_key , selected_nodes))
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True) 
