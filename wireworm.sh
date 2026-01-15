#!/bin/bash
# wireworm.sh - The Hole Punching Wrapper

ROLE=$1 # "sender" or "receiver"
PEER_IP=$2
PEER_PORT=$3
PEER_PUB=$4

if [[ -z "$ROLE" || -z "$PEER_IP" || -z "$PEER_PORT" || -z "$PEER_PUB" ]]; then
    echo "Usage: ./wireworm.sh <sender|receiver> <peer_ip> <peer_port> <peer_pubkey>"
    exit 1
fi

# 1. Local Networking Constants
MY_PRIV=$(wg genkey)
MY_PUB=$(echo "$MY_PRIV" | wg pubkey)
MY_WG_IP=""
PEER_WG_IP=""
LOCAL_PORT=51820

# discovery
echo "Discovering NAT mapping via STUN..."
STUN_OUT=$(stunclient --localport $LOCAL_PORT stun.l.google.com 19302 2>&1 || echo "")
PUB_IP=$(echo "$STUN_OUT" | grep "Mapped address" | cut -d' ' -f3 | cut -d':' -f1)
PUB_PORT=$(echo "$STUN_OUT" | grep "Mapped address" | cut -d' ' -f3 | cut -d':' -f2)

if [[ -n "$PUB_IP" ]]; then
    echo "Your External IP: $PUB_IP"
    echo "Your External Port: $PUB_PORT"
    echo "SHARE THIS WITH PEER!"
fi

if [[ "$ROLE" == "sender" ]]; then
    MY_WG_IP="10.0.0.1/32"
    PEER_WG_IP="10.0.0.2/32"
    
    # Configuration for Sender
    cat <<EOF > wireworm.conf
[Interface]
PrivateKey = $MY_PRIV
Address = $MY_WG_IP
ListenPort = $LOCAL_PORT

[Peer]
PublicKey = $PEER_PUB
Endpoint = $PEER_IP:$PEER_PORT
AllowedIPs = $PEER_WG_IP
PersistentKeepalive = 10

# Expose the local file server to the WireGuard network
[TCPServerTunnel]
ListenPort = 9000
Target = 127.0.0.1:8080
EOF
    echo "Starting Sender File Server..."
    FILE_TO_SEND=${5:-"wormhole_package.txt"}
    if [ ! -f "$FILE_TO_SEND" ]; then
        echo "Creating dummy bundle: $FILE_TO_SEND"
        echo "Hello from WireWorm! This file was transferred via userspace WireGuard hole punching." > "$FILE_TO_SEND"
    fi
    go run test_utils/wireworm_sender.go "$FILE_TO_SEND" &
    
else
    MY_WG_IP="10.0.0.2/32"
    PEER_WG_IP="10.0.0.1/32"

    # Configuration for Receiver
    cat <<EOF > wireworm.conf
[Interface]
PrivateKey = $MY_PRIV
Address = $MY_WG_IP
ListenPort = $LOCAL_PORT

[Peer]
PublicKey = $PEER_PUB
Endpoint = $PEER_IP:$PEER_PORT
AllowedIPs = $PEER_WG_IP
PersistentKeepalive = 10

# Reach the Sender's file server via local port 9001
[TCPClientTunnel]
BindAddress = 127.0.0.1:9001
Target = 10.0.0.1:9000
EOF
fi

echo "Your PubKey: $MY_PUB"
echo "Starting wireproxy..."
./wireproxy -c wireworm.conf
