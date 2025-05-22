#!/usr/bin/env bash

REPLICA_ID=$(hostname | cut -d'.' -f2)
export REPLICA_NAME="onion-$REPLICA_ID"

touch .env

echo "REPLICA_NAME=$REPLICA_NAME" >> .env

ADDRESS=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo "ADDRESS=$ADDRESS" >> .env

python3 onion.py & /usr/local/bin/node_exporter