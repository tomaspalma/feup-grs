from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, timezone

import random
import os
import socket
import requests
import uuid
import time

load_dotenv()

app = Flask(__name__)
flask_startup_time = time.time()
warming_up = True

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
    global warming_up
    identities = Identity.query.all()

    if warming_up and time.time() - flask_startup_time > 60:
        warming_up = False            

    if not warming_up: # Prometheus takes a while to start up, can only use its metrics after 60 seconds
        # Filter out nodes that are not alive
        up_nodes = requests.get(os.getenv('PROMETHEUS_URL'), params={'query': 'up'}).json()
        up_nodes = [node['metric']['instance'].split(':')[0] for node in up_nodes['data']['result'] if node['value'][1] == '1']
        identities = list(filter(lambda x: x.address in up_nodes, identities))

        # Sort nodes by network traffic
        metric = requests.get(os.getenv('PROMETHEUS_URL'), params={'query': 'rate(node_network_transmit_bytes_total{device="eth0"}[5m])'}).json()
        metric = {node['metric']['instance'].split(':')[0]: float(node['value'][1]) for node in metric['data']['result']} 
        identities.sort(key=lambda x: metric.get(x.address, 0))

    selected_nodes = []
    while len(selected_nodes) < 3 and len(identities) > 0:
        if warming_up:
            candidate = random.choice(identities)
        else:
            candidate = identities[0]
        identities.remove(candidate)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((candidate.address, int(candidate.port)))
        except Exception as e:
            print(f"Error connecting to {candidate.address}:{candidate.port} - {e}", flush=True)
            continue
        
        selected_nodes.append((candidate, sock))

    circuit_id = str(uuid.uuid4())
    # Send circuit information to nodes
    for i in range(len(selected_nodes)):
        sock = selected_nodes[i][1]

        right = "None" if i == len(selected_nodes)-1 else selected_nodes[i+1][0].address
        left = request.remote_addr if i == 0 else selected_nodes[i-1][0].address
    
        message = f"controller_setup,{circuit_id},{left},{right},END".encode()
        try:
            sock.sendall(message)
        except Exception as e:
            print("Error sending message: ", e, flush=True)
            continue
        finally:
            sock.close()
    
        print("Message sent: ", message, flush=True)

    # Return circuit to client
    return {
        "id": circuit_id,
        "circuit": list(map(lambda x: { "address": x[0].address, "port": x[0].port }, selected_nodes)),
        "keys": list(map(lambda x: x[0].public_key , selected_nodes))
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True) 
