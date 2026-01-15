#!/bin/bash
set -e

# Colors for "Wow" factor
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}      🪱  WIRE-WORM: NAT HOLE PUNCHING PoC         ${NC}"
echo -e "${CYAN}====================================================${NC}"
echo ""

# 1. Dependency Check
if ! command -v wg &> /dev/null; then
    echo -e "${RED}Error: 'wg' command (wireguard-tools) not found.${NC}"
    exit 1
fi

if [ ! -f "./wireproxy" ]; then
    echo -e "${YELLOW}Building wireproxy...${NC}"
    make > /dev/null
fi

# 2. Key Generation
PRIV=$(wg genkey)
PUB=$(echo "$PRIV" | wg pubkey)
PUB_IP=$(curl -s https://api.ipify.org || echo "unknown")

# 3. Mode Selection
echo -e "${BLUE}Who are you?${NC}"
echo "1) Sender   (I have a file to send)"
echo "2) Receiver (I want to download a file)"
echo -ne "${YELLOW}Select [1-2]: ${NC}"
read MODE

if [[ "$MODE" == "1" ]]; then
    ROLE="sender"
    WG_IP="10.0.0.1/32"
    PEER_WG_IP="10.0.0.2/32"
    LOCAL_WG_PORT=51820
    TUNNEL_INFO="Exposing local file server on WireGuard:9000"
else
    ROLE="receiver"
    WG_IP="10.0.0.2/32"
    PEER_WG_IP="10.0.0.1/32"
    LOCAL_WG_PORT=51820
    TUNNEL_INFO="Mapping remote file server to localhost:9001"
fi

echo -e "\n${GREEN}--- YOUR SIGNAL DATA (Share this with your peer) ---${NC}"
echo -e "${YELLOW}Public IP:  ${NC}$PUB_IP"
echo -e "${YELLOW}UDP Port:   ${NC}$LOCAL_WG_PORT"
echo -e "${YELLOW}Public Key: ${NC}$PUB"
echo -e "${GREEN}---------------------------------------------------${NC}\n"

# 4. Input Peer Data
echo -e "${BLUE}Enter Peer Information:${NC}"
echo -ne "${YELLOW}Peer Public IP: ${NC}"
read PEER_IP
echo -ne "${YELLOW}Peer UDP Port:  ${NC}"
read PEER_PORT
echo -ne "${YELLOW}Peer Public Key: ${NC}"
read PEER_PUB

# 5. File selection for sender
FILE_TO_SEND=""
if [[ "$ROLE" == "sender" ]]; then
    echo -ne "${YELLOW}File path to send (drag file here): ${NC}"
    read FILE_INPUT
    FILE_TO_SEND=$(echo "$FILE_INPUT" | sed "s/'//g" | sed 's/\\//g') # Clean drag-and-drop paths
    if [ ! -f "$FILE_TO_SEND" ]; then
        echo -e "${YELLOW}File not found. Using default dummy file.${NC}"
        FILE_TO_SEND="wormhole_package.txt"
        echo "Hello from WireWorm! This file was transferred via userspace WireGuard hole punching." > "$FILE_TO_SEND"
    fi
fi

# 6. Generate Config
cat <<EOF > wireworm.conf
[Interface]
PrivateKey = $PRIV
Address = $WG_IP
ListenPort = $LOCAL_WG_PORT

[Peer]
PublicKey = $PEER_PUB
Endpoint = $PEER_IP:$PEER_PORT
AllowedIPs = $PEER_WG_IP
PersistentKeepalive = 10
EOF

if [[ "$ROLE" == "sender" ]]; then
    echo -e "\n[TCPServerTunnel]\nListenPort = 9000\nTarget = 127.0.0.1:8080" >> wireworm.conf
    echo -e "${GREEN}Starting Receiver-ready file server...${NC}"
    go run test_utils/wireworm_sender.go "$FILE_TO_SEND" &
    SERVER_PID=$!
    trap 'kill $SERVER_PID 2>/dev/null' EXIT
else
    echo -e "\n[TCPClientTunnel]\nBindAddress = 127.0.0.1:9001\nTarget = 10.0.0.1:9000" >> wireworm.conf
fi

echo -e "${CYAN}PUNCHING HOLE...${NC}"
echo -e "${YELLOW}Wait for 'handshake response' logs, then download the file.${NC}"
if [[ "$ROLE" == "receiver" ]]; then
    echo -e "${GREEN}Command to download: ${NC}curl http://127.0.0.1:9001/download -o downloaded_file"
fi
echo ""

./wireproxy -c wireworm.conf
