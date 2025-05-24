#!/usr/bin/env bash

touch .env

ADDRESS=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo "ADDRESS=$ADDRESS" >> .env

ufw enable
ufw allow 9000

python3 onion.py & /usr/local/bin/node_exporter