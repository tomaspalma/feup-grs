FROM ubuntu:20.04

RUN apt update && apt install -y python3 python3-pip

RUN pip3 install --upgrade pip && \
    pip3 install requests python-dotenv cryptography

WORKDIR /client

COPY . .

CMD tail -f /dev/null
