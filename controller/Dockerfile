FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip install --upgrade pip && \
    pip install eventlet==0.30.2 && dnspython==2.2.1 && \
    pip install ryu flask

COPY *.py /controller/

CMD ryu-manager /controller/sdn.py & python3 /controller/server.py
