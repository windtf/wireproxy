# WireWorm PoC: Userspace WireGuard File Transfer

WireWorm is a Proof of Concept (PoC) demonstrating how to leverage **wireproxy** (a userspace WireGuard client) for secure, end-to-end encrypted file transfers between two peers behind consumer NATs using **NAT Hole Punching**.

## How it Works

Standard file transfer tools often rely on a central relay (like Magic Wormhole's transit relay) to bypass NAT. WireWorm instead uses WireGuard's native ability to punch holes in UDP firewalls.

1.  **Consistent Port Binding**: Both peers bind to a specific local UDP port (e.g., 51820).
2.  **UDP Hole Punching**: Both peers simultaneously attempt to send packets to each other's public IP/Port. This "punches" a hole in the NAT firewall.
3.  **Userspace Networking**: Using `wireproxy` with `gVisor netstack`, a full TCP/IP stack is established over the WireGuard tunnel entirely in userspace.
4.  **Tunnels**:
    *   The **Sender** exposes a local HTTP file server via a `[TCPServerTunnel]` on the WireGuard interface.
    *   The **Receiver** maps the sender's WireGuard IP/Port to a local port using a `[TCPClientTunnel]`.

## Components

- `wireworm.sh`: A wrapper script that generates WireGuard keys, creates the `wireproxy` configuration, and sets up the tunnels.
- `wireworm_sender.go`: A simple Go-based HTTP server that serves a file for transfer.

## Usage (Simulated over Internet)

### 1. Signaling (Exchange Info)
You need to exchange:
- Public IP
- Public Port (UDP)
- WireGuard Public Key

### 2. Run the Sender
```bash
./wireworm.sh sender <RECEIVER_PUBLIC_IP> <RECEIVER_PORT> <RECEIVER_PUBKEY>
```

### 3. Run the Receiver
```bash
./wireworm.sh receiver <SENDER_PUBLIC_IP> <SENDER_PORT> <SENDER_PUBKEY>
```

### 4. Transfer the File
On the receiver machine:
```bash
curl http://127.0.0.1:9001/download -o received_file.txt
```

## Why WireWorm?

- **No Root Required**: Everything runs in userspace.
- **VPN Security**: Inherits the Noise Protocol encryption and security of WireGuard.
- **Resilient**: TCP-over-WireGuard handles packet loss and congestion better than raw UDP transfers.
- **Versatile**: Once the tunnel is up, you aren't limited to file transfers. You have a full private network between the two peers.
