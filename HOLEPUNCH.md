# NAT Hole Punching for WireProxy

This feature adds NAT hole punching capability to wireproxy, enabling peer-to-peer WireGuard tunnel establishment without manual IP/port configuration.

## Quick Start

### Host (expose a service like Minecraft)
```bash
./wireproxy --holepunch --expose 25565
```

You'll see:
```
🔍 Discovering NAT mapping...
✓ NAT discovered: 203.0.113.5:51820

═══════════════════════════════════
  Share this code with your peer:
  93-raven-honey
═══════════════════════════════════
```

### Joiner (connect to friend's service)
```bash
./wireproxy --holepunch --code 93-raven-honey --local 25565
```

Then connect to `localhost:25565` to reach your friend's server.

---

## Manual Testing Steps

### Prerequisites
```bash
go build ./cmd/wireproxy
go build ./cmd/rendezvous
```

### Test 1: STUN Discovery
```bash
./wireproxy --holepunch --expose 25565
# Should show your public IP and a wormhole code
# Press Ctrl+C to exit
```

### Test 2: Full Exchange (Local)

**Terminal 1 - Rendezvous Server:**
```bash
./rendezvous
```

**Terminal 2 - Host:**
```bash
./wireproxy --holepunch --expose 8080
# Note the code shown (e.g., "42-banana-sunset")
```

**Terminal 3 - Joiner:**
```bash
./wireproxy --holepunch --code 42-banana-sunset --local 8080
```

### Test 3: Manual Fallback (No Server)

If rendezvous is unavailable, the tool falls back to manual mode:
```
⚠️  Rendezvous server unavailable. Using manual exchange.

Your connection string:
  hp://ABC123...@203.0.113.5:51820

Paste peer's connection string: _
```

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--holepunch` | Enable NAT hole punching mode |
| `--expose <port>` | Host mode: expose this local port |
| `--code <code>` | Join mode: peer's wormhole code |
| `--local <port>` | Join mode: local port to bind |

---

## Known Limitations

⚠️ **Docker Desktop**: NAT hole punching does NOT work inside Docker containers on Mac/Windows due to VPNKit/gVisor symmetric NAT. Run wireproxy natively on the host instead.
