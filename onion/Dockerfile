FROM ubuntu:22.04

RUN apt update && apt install -y \
    iproute2 curl wget && \
    # Install node_exporter for monitoring
    wget https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz && \
    tar -xvzf node_exporter-1.9.1.linux-amd64.tar.gz && \
    mv node_exporter-1.9.1.linux-amd64/node_exporter /usr/local/bin/ && \
    rm -rf node_exporter-1.9.1.linux-amd64*    

CMD /usr/local/bin/node_exporter
