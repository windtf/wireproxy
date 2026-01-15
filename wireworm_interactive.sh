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

if ! command -v stunclient &> /dev/null; then
    echo -e "${YELLOW}Installing STUN client for NAT discovery...${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install stuntman > /dev/null
    else
        sudo apt-get update && sudo apt-get install -y stun-client > /dev/null
    fi
fi

if [ ! -f "./wireproxy" ]; then
    echo -e "${YELLOW}Building wireproxy...${NC}"
    make > /dev/null
fi

# 2. Key Generation
PRIV=$(wg genkey)
PUB=$(echo "$PRIV" | wg pubkey)

# --- NAT Discovery ---
# Use a random local port for better punch-through and to avoid conflicts
LOCAL_WG_PORT=$((RANDOM % 55535 + 10000))

echo -e "${BLUE}Discovering NAT mapping using local port $LOCAL_WG_PORT...${NC}"
# Try multiple servers if one is down
STUN_SERVERS=("stun.l.google.com:19302" "stunserver.org:3478" "stun.voip.blackberry.com:3478")
STUN_OUT=""

for s in "${STUN_SERVERS[@]}"; do
    server=$(echo $s | cut -d':' -f1)
    port=$(echo $s | cut -d':' -f2)
    STUN_OUT=$(stunclient --localport $LOCAL_WG_PORT $server $port 2>&1 || echo "")
    if [[ "$STUN_OUT" == *"Mapped address"* ]]; then
        break
    fi
done

PUB_IP=$(echo "$STUN_OUT" | grep -oE "Mapped address: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" | cut -d' ' -f3 | cut -d':' -f1 || echo "")
PUB_PORT=$(echo "$STUN_OUT" | grep -oE "Mapped address: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" | cut -d' ' -f3 | cut -d':' -f2 || echo "")

if [[ -z "$PUB_IP" || -z "$PUB_PORT" ]]; then
    echo -e "${YELLOW}Warning: STUN discovery failed. Falling back to simple IP discovery.${NC}"
    PUB_IP=$(curl -s https://api.ipify.org || echo "unknown")
    PUB_PORT=$LOCAL_WG_PORT
fi

# --- Validation Functions ---
validate_ip() {
    local ip=$1
    # Simple regex for IPv4 or hostname
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ $ip =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 0
    fi
    return 1
}

validate_port() {
    if [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; then
        return 0
    fi
    return 1
}

validate_pubkey() {
    # WireGuard keys are 44 chars including base64 padding
    if [[ $1 =~ ^[a-zA-Z0-9+/]{42,43}=$ ]]; then
        return 0
    fi
    return 1
}

sanitize() {
    echo "$1" | tr -d '[:cntrl:]' | xargs
}

# 3. Mode Selection
while true; do
    echo -e "${BLUE}What would you like to do?${NC}"
    echo "1) Send File"
    echo "2) Receive File"
    echo "3) Start Chat (Host)"
    echo "4) Join Chat"
    echo -ne "${YELLOW}Select [1-4]: ${NC}"
    read MODE
    MODE=$(sanitize "$MODE")
    if [[ "$MODE" =~ ^[1-4]$ ]]; then break; fi
    echo -e "${RED}Invalid selection.${NC}"
done

if [[ "$MODE" == "1" || "$MODE" == "3" ]]; then
    ROLE="host"
    WG_IP="10.0.0.1/32"
    PEER_WG_IP="10.0.0.2/32"
    if [[ "$MODE" == "1" ]]; then SUB_MODE="file"; else SUB_MODE="chat"; fi
else
    ROLE="joiner"
    WG_IP="10.0.0.2/32"
    PEER_WG_IP="10.0.0.1/32"
    if [[ "$MODE" == "2" ]]; then SUB_MODE="file"; else SUB_MODE="chat"; fi
fi

echo -e "\n${GREEN}--- YOUR CONNECTION STRING (Share this with your peer) ---${NC}"
echo -e "${YELLOW}CONNECTION:${NC} ${CYAN}$PUB_IP:$PUB_PORT:$PUB${NC}"
echo -e "${GREEN}---------------------------------------------------${NC}\n"

# Start a background "Hole Maintainer" to keep the NAT mapping from expiring
# while the user is typing the peer information.
(
    while true; do
        # Sending a tiny packet to the stun server to keep the mapping active
        stunclient --localport $LOCAL_WG_PORT stun.l.google.com 19302 &> /dev/null
        sleep 20
    done
) &
MAINTAINER_PID=$!
trap 'kill $MAINTAINER_PID 2>/dev/null || true' EXIT

# 4. Input Peer Data
echo -e "${BLUE}Enter Peer Information:${NC}"
while true; do
    echo -ne "${YELLOW}Paste Peer Connection String: ${NC}"
    read PEER_INPUT
    PEER_INPUT=$(sanitize "$PEER_INPUT")
    
    PEER_IP=$(echo "$PEER_INPUT" | cut -d':' -f1)
    PEER_PORT=$(echo "$PEER_INPUT" | cut -d':' -f2)
    PEER_PUB=$(echo "$PEER_INPUT" | cut -d':' -f3)

    if validate_ip "$PEER_IP" && validate_port "$PEER_PORT" && validate_pubkey "$PEER_PUB"; then
        break
    fi
    echo -e "${RED}Invalid connection string. Expected format: IP:PORT:PUBKEY${NC}"
done

# 5. File selection for sender
FILE_TO_SEND=""
if [[ "$SUB_MODE" == "file" && "$ROLE" == "host" ]]; then
    echo -ne "${YELLOW}File path to send (drag file here): ${NC}"
    read FILE_INPUT
    FILE_TO_SEND=$(echo "$FILE_INPUT" | sed "s/'//g" | sed 's/\\//g' | xargs)
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

if [[ "$ROLE" == "host" ]]; then
    if [[ "$SUB_MODE" == "file" ]]; then
        echo -e "\n[TCPServerTunnel]\nListenPort = 9000\nTarget = 127.0.0.1:8080" >> wireworm.conf
        echo -e "${GREEN}Starting Receiver-ready file server...${NC}"
        go run test_utils/wireworm_sender.go "$FILE_TO_SEND" &
        SERVER_PID=$!
    else
        echo -e "\n[TCPServerTunnel]\nListenPort = 9002\nTarget = 127.0.0.1:8082" >> wireworm.conf
        echo -e "${GREEN}Preparing Chat Host...${NC}"
        # We will start the actual chat tool AFTER wireproxy is up
    fi
else
    if [[ "$SUB_MODE" == "file" ]]; then
        echo -e "\n[TCPClientTunnel]\nBindAddress = 127.0.0.1:9001\nTarget = 10.0.0.1:9000" >> wireworm.conf
    else
        echo -e "\n[TCPClientTunnel]\nBindAddress = 127.0.0.1:9003\nTarget = 10.0.0.1:9002" >> wireworm.conf
    fi
fi

echo -e "${CYAN}PUNCHING HOLE...${NC}"
if [[ "$SUB_MODE" == "file" ]]; then
    echo -e "${YELLOW}Wait for 'handshake response' logs, then download the file.${NC}"
    if [[ "$ROLE" == "joiner" ]]; then
        echo -e "${GREEN}Command to download: ${NC}curl http://127.0.0.1:9001/download -o downloaded_file"
    fi
else
    echo -e "${YELLOW}Wait for handshake, then chat will begin.${NC}"
fi

# Start wireproxy with the info server enabled for handshake monitoring
./wireproxy -c wireworm.conf -i 127.0.0.1:8081 > wireproxy.log 2>&1 &
WIREPROXY_PID=$!

# Handshake Monitor Loop
echo -e "${BLUE}Monitoring Connection Status...${NC}"
(
    while kill -0 $WIREPROXY_PID 2>/dev/null; do
        METRICS=$(curl -s http://127.0.0.1:8081/metrics || echo "")
        HANDSHAKE=$(echo "$METRICS" | grep "last_handshake_time_sec" | cut -d'=' -f2 || echo "0")
        
        if [ "$HANDSHAKE" -ne "0" ] && [ ! -z "$HANDSHAKE" ]; then
            echo -e "\n${GREEN}====================================================${NC}"
            echo -e "${GREEN}         🚀 SUCCESS: HOLE PUNCHED!                 ${NC}"
            echo -e "${GREEN}====================================================${NC}"
            if [[ "$OSTYPE" == "darwin"* ]]; then
                HS_TIME=$(date -r $HANDSHAKE)
            else
                HS_TIME=$(date -d @$HANDSHAKE)
            fi
            echo -e "${CYAN}Handshake established at: $HS_TIME${NC}"
            echo -e "${YELLOW}WireWorm tunnel is active.${NC}"
            if [[ "$SUB_MODE" == "file" ]]; then
                if [[ "$ROLE" == "joiner" ]]; then
                    echo -e "${GREEN}You can now run the curl command in another terminal.${NC}"
                fi
                # Keep monitoring but slow down
                sleep 60
            else
                echo -e "${GREEN}Starting Chat Session...${NC}"
                if [[ "$ROLE" == "host" ]]; then
                    go run test_utils/wireworm_chat.go server 8082
                else
                    go run test_utils/wireworm_chat.go client 127.0.0.1:9003
                fi
                # Once chat exits, kill everything
                kill $WIREPROXY_PID 2>/dev/null || true
                exit 0
            fi
        else
            echo -ne "${YELLOW}Listening for peer... (No handshake yet) \r${NC}"
        fi
        sleep 2
    done
) &
MONITOR_PID=$!

# Handle shutdown
trap 'kill $WIREPROXY_PID $SERVER_PID $MAINTAINER_PID $MONITOR_PID 2>/dev/null || true; exit' INT TERM EXIT

wait $WIREPROXY_PID
