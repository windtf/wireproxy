# Docker NAT Hole Punching Analysis

## The Issue: "Symmetric NAT" in Docker Desktop

We successfully hole-punched natively on macOS, but failed consistently when running the same logic inside a Docker container on Docker Desktop (Mac/Windows).

### Root Cause Analysis

UDP Hole Punching relies on a critical assumption: **Cone NAT**.
> The router must map `InternalIP:Port` to the **same** `ExternalIP:Port` regardless of the destination address.

1.  **Native Execution**: macOS Kernel -> Router (Cone NAT) -> Internet.
    *   Request to STUN Server -> Source Port `51820` preserved (or mapped consistently).
    *   Request to Peer -> Source Port `51820` preserved.
    *   **Result**: Success.

2.  **Docker Desktop Execution**: Container -> **Linux VM Bridge** -> **VPNKit Userland Proxy** -> Host OS -> Router -> Internet.
    *   This translation layer often behaves as **Symmetric NAT**.
    *   Request to STUN Server: Mapped to External Port `32001`.
    *   Request to Peer: Mapped to External Port `45002`.
    *   **Result**: The peer tries to reply to `32001` (what STUN saw), but your firewall expects traffic on `45002`. Packet dropped.

## Proposed Solutions

To successfully containerize this utility, we must bypass the Docker Desktop networking abstraction.

### 1. Host Networking (Linux Only)
On native Linux, `--network host` shares the host's networking stack directly.
*   **Feasibility**: High (Linux), Zero (Mac/Windows).
*   **Command**: `docker run --network host ...`
*   **Limitation**: On Docker Desktop, this only shares the *Linux VM's* network, not the Mac/Windows Host network, so it remains double-natted.

### 2. Macvlan Network Driver
Giving the container its own IP address on the local LAN, bypassing the host's NAT entirely.
*   **Feasibility**: Medium. Requires network configuration access.
*   **Command**:
    ```bash
    docker network create -d macvlan --subnet=192.168.1.0/24 --gateway=192.168.1.1 -o parent=en0 pub_net
    docker run --net pub_net ...
    ```
*   **Pros**: Makes the container appear as a physical device on the network.
*   **Cons**: Wireless adapters (WiFi) often reject macvlan traffic due to security features (only one MAC address allowed per client).

### 3. UDP Port Preservation (High Difficulty)
We need a way to force Docker's outbound NAT to preserve the source port.
*   **Method**: Utilize `iptables` inside the Docker VM (if accessible) to set SNAT rules.
*   **Complexity**: Docker Desktop does not easily allow modifying the VM's `iptables`.

### 4. Hybrid Approach (The "Sidecar")
Run the `wireproxy` logic in the container, but run the networking/socket layer on the host.
*   **Method**: This effectively defeats the purpose of containerization (portability).

## Conclusion
For **UDP Hole Punching**, the physical network layer is leaking into the abstraction. Docker Desktop's default networking mode is fundamentally incompatible with the requirement of "Endpoint-Independent Mapping" needed for P2P connection establishment without a relay.

**Recommendation**: Detect the environment. If Docker is detected, warn the user that hole punching may fail unless they are on native Linux or using advanced network drivers (Macvlan).
