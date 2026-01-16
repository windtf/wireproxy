# Specification: Go Windows P2P DNS Library (winp2pns)

## 1. Core Objectives
* **Namespace Scoping:** Intercept ONLY developer-defined domains (e.g., `*.p2p.local`) to ensure zero interference with the user's other web traffic.
* **Port Transparency:** Use DNS SRV records to map a friendly domain name to a dynamic local proxy port, removing the need for users to type ports in the game client.
* **Seamless Failover:** Implement a 0-TTL (Time-to-Live) policy to allow the utility to switch between P2P and Relay IPs/Ports instantly.
* **System Integration:** Utilize the Windows Name Resolution Policy Table (NRPT) for "Split-Horizon" DNS without modifying global network adapter settings.

---

## 2. Component Architecture

### 2.1 NRPT Manager (Registry Integration)
The library manipulates the Windows NRPT to tell the OS: *"If a query ends in .p2p.local, ask the DNS server at 127.0.0.1; otherwise, use the ISP."*

**Registry Path:**
`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\{GUID}`

| Value Name | Type | Value / Purpose |
| :--- | :--- | :--- |
| `Name` | REG_MULTI_SZ | The namespace suffix (e.g., `.p2p.local`) |
| `GenericDNSServers` | REG_SZ | `127.0.0.1` |
| `ConfigOptions` | REG_DWORD | `1` (Enables the rule) |

### 2.2 DNS Responder (UDP 53)
A lightweight DNS server implemented using the `github.com/miekg/dns` package.

* **Listener:** Binds to `127.0.0.1:53` (UDP).
* **Authoritative Flag:** All responses must have the `Authoritative` bit set to true.
* **Caching Policy:** All Resource Records (RRs) must have a `TTL` of `0`.

### 2.3 State Provider (Interface)
The library consumes an interface to retrieve real-time tunnel information.

```go
type ProxyState struct {
    LocalPort uint16 // The local port the proxy is currently listening on
    IsActive  bool   // If false, the DNS server returns RCODE_NAME_ERROR or RCODE_REFUSED
}

type TunnelProvider interface {
    GetProxyState(hostname string) (ProxyState, error)
}
```

---

## 3. Technical Workflow

### 3.1 Initialization Sequence
1. **Privilege Validation:** Check if the process has Administrative/System privileges.
2. **Namespace Registration:** Generate a unique GUID and create the NRPT registry subkey.
3. **Socket Binding:** Attempt to bind to UDP port 53 on `127.0.0.1`.
    * *Fallback:* If port 53 is blocked, notify the user or attempt to bind to `127.0.0.2`.
4. **Service Start:** Start the `dns.Server` loop.

### 3.2 DNS Query Resolution Logic
When a DNS query is received:

1. **Suffix Validation:** If the query does not match the registered namespace, ignore or return `RCODE_REFUSED`.
2. **Minecraft SRV Handling:**
    * **Query:** `_minecraft._tcp.[server].p2p.local` (Type: SRV)
    * **Response (Answer):** `SRV 0 0 [ProxyState.LocalPort] tunnel.[server].p2p.local`
    * **Response (Additional):** `tunnel.[server].p2p.local A 127.0.0.1`
3. **Standard A-Record Handling:**
    * **Query:** `[any].p2p.local` (Type: A)
    * **Response:** `A 127.0.0.1`



### 3.3 Cleanup Sequence
On application exit (Signal or Graceful):
1. Stop the DNS listener loop.
2. Delete the specific GUID subkey from `HKLM\...\DnsPolicyConfig`.
3. Flush the Windows DNS cache via `dnscache` service or `ipconfig /flushdns` command.

---

## 4. Proposed Go Package Structure

```text
winp2pns/
├── nrpt_windows.go  # NRPT logic using golang.org/x/sys/windows/registry
├── dns_handler.go   # UDP server logic using github.com/miekg/dns
├── provider.go      # Interface and state struct definitions
└── privilege.go     # Manifest/Token checks for Admin rights
```

## 5. Implementation Constraints
* **Conflict Management:** The library must handle cases where the NRPT registry key already exists from a previous crash by overwriting it with the new local configuration.
* **Response Latency:** Since Minecraft checks DNS before connecting, the `TunnelProvider.GetProxyState` call must be non-blocking or extremely low-latency.
* **Bedrock Support:** For Bedrock edition, if SRV records are ignored, the utility should ideally attempt to use the default port `19132` locally to ensure a "port-less" experience.