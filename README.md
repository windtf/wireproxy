# wireproxy

[![ISC licensed](https://img.shields.io/badge/license-ISC-blue)](./LICENSE)
[![Build status](https://github.com/octeep/wireproxy/actions/workflows/build.yml/badge.svg)](https://github.com/octeep/wireproxy/actions)
[![Documentation](https://img.shields.io/badge/godoc-wireproxy-blue)](https://pkg.go.dev/github.com/octeep/wireproxy)

A wireguard client that exposes itself as a socks5/http proxy or tunnels.

# What is this

`wireproxy` is a completely userspace application that connects to a wireguard peer,
and exposes a socks5/http proxy or tunnels on the machine. This can be useful if you need
to connect to certain sites via a wireguard peer, but can't be bothered to setup a new network
interface for whatever reasons.

# Sponsor

<a href="https://proxy-seller.com/?partner=1Z1IPV519ZG31Q"><img src="./assets/proxy-seller.png" width="300" alt="Proxy-Seller"></a>

Use coupon **WIREPROXY** - 15% discount on IPv4, IPv6, ISP, and residential proxies, and 10% off mobile proxies.

[Proxy-Seller](https://proxy-seller.com/?partner=1Z1IPV519ZG31Q) has been in the market since 2014.

They provide IPv4, IPv6, ISP, Residential, and Mobile proxies that support both HTTP(S) and SOCKS5 connection protocols. Additionally, they offer a mobile panel to create your own rotating mobile proxies, and provide easy-to-setup equipment with worldwide shipping. After setting up your own mobile proxies, Proxy-Seller can help you rent them out if the location needs it, allowing you to receive a percentage of the sales. The service offers flexible residential proxy solutions for individuals and businesses, with competitive rates starting at $3.5 per 1GB and a low-cost trial option for $1.99.

Their loyal support team is available to address any issues individually at any time of the day or night. Many customers appreciate this level of support, as well as their very affordable prices, starting from $0.70 per IP.

Proxy-Seller provides proxies for a wide range of use cases, including web scraping, gaming, social media management, multi-accounting, ad verification, market research, e-commerce monitoring, SEO tracking, and automation tasks.

**Outstanding Features:**

1. Mobile panel for your own proxy farms
2. Residential, SOCKS5, HTTPS, mobile, and datacenter proxies
3. Auto-renewal feature for proxies

**Important:** If any technical issues arise, your proxies can be replaced with proxies from other countries, even if those locations are more expensive. Alternatively, support can add a few extra days to your existing proxy package.

# Why you might want this

- You simply want to use wireguard as a way to proxy some traffic.
- You don't want root permission just to change wireguard settings.

Currently, I'm running wireproxy connected to a wireguard server in another country,
and configured my browser to use wireproxy for certain sites. It's pretty useful since
wireproxy is completely isolated from my network interfaces, and I don't need root to configure
anything.

Users who want something similar but for Amnezia VPN can use [this fork](https://github.com/artem-russkikh/wireproxy-awg)
of wireproxy by [@artem-russkikh](https://github.com/artem-russkikh).

# Feature

- TCP static routing for client and server
- SOCKS5/HTTP proxy (currently only CONNECT is supported)

# TODO

- UDP Support in SOCKS5
- UDP static routing

# Usage

```bash
./wireproxy [-c path to config]
```

```bash
usage: wireproxy [-h|--help] [-c|--config "<value>"] [-s|--silent]
                 [-d|--daemon] [-i|--info "<value>"] [-v|--version]
                 [-n|--configtest]

                 Userspace wireguard client for proxying

Arguments:

  -h  --help        Print help information
  -c  --config      Path of configuration file
                    Default paths: /etc/wireproxy/wireproxy.conf, $HOME/.config/wireproxy.conf
  -s  --silent      Silent mode
  -d  --daemon      Make wireproxy run in background
  -i  --info        Specify the address and port for exposing health status
  -v  --version     Print version
  -n  --configtest  Configtest mode. Only check the configuration file for
                    validity.
```

# Build instruction

```bash
git clone https://github.com/octeep/wireproxy
cd wireproxy
make
```

# Install

```bash
go install github.com/windtf/wireproxy/cmd/wireproxy@v1.1.2 # or @latest
```

# Use with VPN

Instructions for using wireproxy with Firefox container tabs and auto-start on MacOS can be found [here](/UseWithVPN.md).

# Sample config file

```ini
# The [Interface] and [Peer] configurations follow the same semantics and meaning
# of a wg-quick configuration. To understand what these fields mean, please refer to:
# https://wiki.archlinux.org/title/WireGuard#Persistent_configuration
# https://www.wireguard.com/#simple-network-interface
[Interface]
Address = 10.200.200.2/32 # The subnet should be /32 and /128 for IPv4 and v6 respectively
# MTU = 1420 (optional)
PrivateKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
# PrivateKey = $MY_WIREGUARD_PRIVATE_KEY # Alternatively, reference environment variables
DNS = 10.200.200.1

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
# PresharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs= (optional)
Endpoint = my.ddns.example.com:51820
# PersistentKeepalive = 25 (optional)

# TCPClientTunnel is a tunnel listening on your machine,
# and it forwards any TCP traffic received to the specified target via wireguard.
# Flow:
# <an app on your LAN> --> localhost:25565 --(wireguard)--> play.cubecraft.net:25565
[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = play.cubecraft.net:25565

# TCPServerTunnel is a tunnel listening on wireguard,
# and it forwards any TCP traffic received to the specified target via local network.
# Flow:
# <an app on your wireguard network> --(wireguard)--> 172.16.31.2:3422 --> localhost:25545
[TCPServerTunnel]
ListenPort = 3422
Target = localhost:25545

# STDIOTunnel is a tunnel connecting the standard input and output of the wireproxy
# process to the specified TCP target via wireguard.
# This is especially useful to use wireproxy as a ProxyCommand parameter in openssh
# For example:
#    ssh -o ProxyCommand='wireproxy -c myconfig.conf' ssh.myserver.net
# Flow:
# Piped command -->(wireguard)--> ssh.myserver.net:22
[STDIOTunnel]
Target = ssh.myserver.net:22

# Socks5 creates a socks5 proxy on your LAN, and all traffic would be routed via wireguard.
[Socks5]
BindAddress = 127.0.0.1:25344

# Socks5 authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...

# http creates a http proxy on your LAN, and all traffic would be routed via wireguard.
[http]
BindAddress = 127.0.0.1:25345

# HTTP authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...

# Specifying certificate and key enables HTTPS
#CertFile = ...
#KeyFile = ...
```

Alternatively, if you already have a wireguard config, you can import it in the
wireproxy config file like this:

```ini
WGConfig = <path to the wireguard config>

# Same semantics as above
[TCPClientTunnel]
...

[TCPServerTunnel]
...

[Socks5]
...
```

Having multiple peers is also supported. `AllowedIPs` would need to be specified
such that wireproxy would know which peer to forward to.

```ini
[Interface]
Address = 10.254.254.40/32
PrivateKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=

[Peer]
Endpoint = 192.168.0.204:51820
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
PersistentKeepalive = 25

[Peer]
PublicKey = ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=
AllowedIPs = 10.254.254.1/32, fdee:1337:c000:d00d::1/128
Endpoint = 172.16.0.185:44044
PersistentKeepalive = 25


[TCPServerTunnel]
ListenPort = 5000
Target = service-one.servicenet:5000

[TCPServerTunnel]
ListenPort = 5001
Target = service-two.servicenet:5001

[TCPServerTunnel]
ListenPort = 5080
Target = service-three.servicenet:80

[UDPProxyTunnel]
BindAddress = 127.0.0.1:53
Target = 1.1.1.1:53
InactivityTimeout = 30 # If its set to 0, it will never timeout

[Resolve]
# Set DNS Resovle Strategy
# `ipv4`: Prioritize A records.
# `ipv6`: Prioritize AAAA records       .
# `auto` (Default): If the WireGuard interface has IPv4 address only, it's equivalent to `ipv4`, otherwise it's equivalent to `ipv6`.
ResolveStrategy = auto 
```

Wireproxy can also allow peers to connect to it:

```ini
[Interface]
ListenPort = 5400
...

[Peer]
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
# Note there is no Endpoint defined here.
```

# Health endpoint

Wireproxy supports exposing a health endpoint for monitoring purposes.
The argument `--info/-i` specifies an address and port (e.g. `localhost:9080`), which exposes a HTTP server that provides health status metric of the server.

Currently two endpoints are implemented:

`/metrics`: Exposes information of the wireguard daemon, this provides the same information you would get with `wg show`. [This](https://www.wireguard.com/xplatform/#example-dialog) shows an example of what the response would look like.

`/readyz`: This responds with a json which shows the last time a pong is received from an IP specified with `CheckAlive`. When `CheckAlive` is set, a ping is sent out to addresses in `CheckAlive` per `CheckAliveInterval` seconds (defaults to 5) via wireguard. If a pong has not been received from one of the addresses within the last `CheckAliveInterval` seconds (+2 seconds for some leeway to account for latency), then it would respond with a 503, otherwise a 200.

For example:

```ini
[Interface]
PrivateKey = censored
Address = 10.2.0.2/32
DNS = 10.2.0.1
CheckAlive = 1.1.1.1, 3.3.3.3
CheckAliveInterval = 3

[Peer]
PublicKey = censored
AllowedIPs = 0.0.0.0/0
Endpoint = 149.34.244.174:51820

[Socks5]
BindAddress = 127.0.0.1:25344
```

`/readyz` would respond with

```text
< HTTP/1.1 503 Service Unavailable
< Date: Thu, 11 Apr 2024 00:54:59 GMT
< Content-Length: 35
< Content-Type: text/plain; charset=utf-8
<
{"1.1.1.1":1712796899,"3.3.3.3":0}
```

And for:

```ini
[Interface]
PrivateKey = censored
Address = 10.2.0.2/32
DNS = 10.2.0.1
CheckAlive = 1.1.1.1
```

`/readyz` would respond with

```text
< HTTP/1.1 200 OK
< Date: Thu, 11 Apr 2024 00:56:21 GMT
< Content-Length: 23
< Content-Type: text/plain; charset=utf-8
<
{"1.1.1.1":1712796979}
```

If nothing is set for `CheckAlive`, an empty JSON object with 200 will be the response.

The peer which the ICMP ping packet is routed to depends on the `AllowedIPs` set for each peers.

# Stargazers over time

[![Stargazers over time](https://starchart.cc/octeep/wireproxy.svg)](https://starchart.cc/octeep/wireproxy)
