FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y python3 python3-pip iputils-ping iproute2 && \
    pip install --upgrade pip && \
    pip install flask psycopg2-binary python-dotenv flask_sqlalchemy requests

WORKDIR /controller

COPY server.py .

CMD python3 server.py
