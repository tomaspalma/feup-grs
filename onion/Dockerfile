FROM ubuntu:22.04

RUN apt update && apt install -y \
    openvswitch-switch \
    iproute2

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD /entrypoint.sh
