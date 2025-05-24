from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, timezone

import random
import os
import socket
import requests

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

@app.route("/circuit", methods=['POST'])
def circuit():
    identities = Identity.query.all()

    # Filter out nodes that are not alive
    up_nodes = requests.get(os.getenv('PROMETHEUS_URL'), params={'query': 'up'}).json()
    up_nodes = [node['metric']['instance'].split(':')[0] for node in up_nodes['data']['result'] if node['value'][1] == '1']
    identities = list(filter(lambda x: x.address in up_nodes, identities))

    # Sort nodes by network traffic
    metric = requests.get(os.getenv('PROMETHEUS_URL'), params={'query': 'node_network_receive_bytes_total[1m]'}).json()
    metric = {node['metric']['instance'].split(':')[0]: float(node['values'][0][1]) for node in metric['data']['result']}
    identities.sort(key=lambda x: metric.get(x.address, 0))

    selected_nodes = []
    while len(selected_nodes) < 3 and len(identities) > 0:
        candidate = random.choice(identities)
        identities.remove(candidate)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((candidate.address, int(candidate.port)))
        except Exception as e:
            print(f"Error connecting to {candidate.address}:{candidate.port} - {e}", flush=True)
            continue
        
        selected_nodes.append((candidate, sock))

    # Send circuit information to nodes
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

    # Return circuit to client
    return {
        "circuit": list(map(lambda x: { "address": x[0].address, "port": x[0].port }, selected_nodes)),
        "keys": list(map(lambda x: x[0].public_key , selected_nodes))
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True) 
