#!/bin/bash

/usr/share/openvswitch/scripts/ovs-ctl start

# Create OVS bridge
ovs-vsctl add-br br0

# Assign IP to bridge
ip addr add $(hostname -i | grep -oP '10.0.3+')/24 dev br0
ip link set br0 up

# Delete default route and add bridge as default
ip route del default
ip route add default dev br0

# Connect to Ryu controller
ovs-vsctl set-controller br0 tcp:10.0.3.254:6633
ovs-vsctl set bridge br0 protocols=OpenFlow13

# Wait and keep container alive
tail -f /dev/null
