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

## Features

- **P2P File Transfer**: High-speed, secure file transfers using standard HTTP over WireGuard.
- **Instant Chat**: Secure, private, end-to-end encrypted chat session between peers.
- **No Root Required**: Everything runs in userspace.
- **NAT Traversal**: Automatic UDP hole punching to bypass restrictive firewalls.

## Usage (Interactive)

The easiest way to use WireWorm is via the interactive script:

```bash
cd wireproxy
bash wireworm_interactive.sh
```

### Usage (Docker)

You can also run WireWorm in a container. 

#### On Linux (Native Docker):
```bash
docker run -it --rm --network host wireworm
```

#### On macOS / Windows (Docker Desktop):
On Mac and Windows, Docker runs inside a virtual machine, so `--network host` doesn't provide direct access to your Mac's network. You must use explicit port mapping:

```bash
docker run -it --rm \
  -e WIRE_PORT=51820 \
  -p 51820:51820/udp \
  wireworm
```

**Why this is necessary:**
- **The Chain**: `Internet (Public Port)` $\to$ `Router` $\to$ `Mac/Win (Host Port)` $\to$ `Docker VM` $\to$ `Container (Local Port)`.
- Without `-p`, your Mac doesn't know to forward incoming P2P packets from the internet into the Docker VM.
- **WIRE_PORT** ensures the script inside Docker actually uses the port you've opened on your host.

1.  **Select Mode**: Choose between File Transfer or Chat.
2.  **Exchange Connection String**: The script will provide a single string (e.g., `IP:PORT:PUBKEY`) to share with your peer.
3.  **Establish Secure Tunnel**: Once both peers enter each other's strings, the NAT hole is punched and the WireGuard handshake begins.
4.  **Interact**:
    *   **In Chat Mode**: The chat session will begin automatically in your terminal.
    *   **In File Mode**: Use the provided `curl` command to download the file.
