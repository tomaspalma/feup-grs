FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip install --upgrade pip && \
    pip install flask

COPY server.py /controller/server.py

CMD python3 /controller/server.py
