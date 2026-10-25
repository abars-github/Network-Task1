#!/bin/sh
# Netfilter rules for one device.  Run as root.  Usage:
#   setup_rules.sh <LAN_IF> <PEER_IF> <LOCAL_PC_NET> <REMOTE_PC_NET> <PROTECTED_PORT> [QUEUE]
# Example Device1: setup_rules.sh eth0 eth1 10.0.1.0/24 10.0.2.0/24 8080
# Example Device2: setup_rules.sh eth1 eth0 10.0.2.0/24 10.0.1.0/24 8080
#   (on Device2 LAN_IF faces PC2, PEER_IF faces Device1)
# Traffic whose *server* port is PROTECTED_PORT is protected in both directions.
set -e
LAN=$1; PEER=$2; LOCALNET=$3; REMOTENET=$4; PORT=$5; Q=${6:-0}
CTL=9000

sysctl -w net.ipv4.ip_forward=1 >/dev/null
# the payload grows by 16 bytes: keep MSS low enough (or lower PC MTU) to avoid fragmentation
iptables -t mangle -N SECLINK 2>/dev/null || iptables -t mangle -F SECLINK
iptables -t mangle -F FORWARD

# PC -> peer device (encrypt):  client->server and server->client data of the protected port
iptables -t mangle -A FORWARD -i "$LAN" -o "$PEER" -s "$LOCALNET" -d "$REMOTENET" -p tcp \
    -m multiport --dports "$PORT" -j MARK --set-mark 1
iptables -t mangle -A FORWARD -i "$LAN" -o "$PEER" -s "$LOCALNET" -d "$REMOTENET" -p tcp \
    -m multiport --sports "$PORT" -j MARK --set-mark 1
# peer device -> PC (decrypt)
iptables -t mangle -A FORWARD -i "$PEER" -o "$LAN" -s "$REMOTENET" -d "$LOCALNET" -p tcp \
    -m multiport --dports "$PORT" -j MARK --set-mark 2
iptables -t mangle -A FORWARD -i "$PEER" -o "$LAN" -s "$REMOTENET" -d "$LOCALNET" -p tcp \
    -m multiport --sports "$PORT" -j MARK --set-mark 2
# hand marked packets to userspace; fail-closed (no --queue-bypass) so nothing leaks in clear
iptables -t mangle -A FORWARD -m mark --mark 1 -j NFQUEUE --queue-num "$Q"
iptables -t mangle -A FORWARD -m mark --mark 2 -j NFQUEUE --queue-num "$Q"

# TCP checksum offload would hand us packets with unfinished checksums; we recompute anyway,
# but disable offloads so what we emit is what is sent.
for i in "$LAN" "$PEER"; do ethtool -K "$i" rx off tx off gso off gro off tso off 2>/dev/null || true; done
# reduce MSS so payload+16 still fits the MTU
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
echo "rules installed (control channel: tcp/$CTL between the devices, not forwarded traffic)"
