from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime

import os

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

    print("ID: ", id)
    print("PUBLIC_KEY: ", public_key)
    print("ADDRESS: ", address)

    existing_identity = Identity.query.filter_by(name=id).first()
    if existing_identity:
        existing_identity.public_key = public_key
        existing_identity.address = address
        existing_identity.last_updated = datetime.utcnow()

        db.session.commit()
    else:
        identity = Identity(
            name=id,
            public_key=public_key,
            address=address,
            last_updated=datetime.utcnow()
        )

        db.session.add(identity)
        db.session.commit()

    return json

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True) 
