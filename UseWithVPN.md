# Getting a Wireguard Server

You can create your own wireguard server using a host service like DigitalOcean,
or you can get a VPN service that provides WireGuard configs.

I recommend ProtonVPN, because it is highly secure and has a great WireGuard
config generator.

Simply go to <https://account.protonvpn.com/downloads> and scroll down to the
wireguard section to generate your configs, then paste into the appropriate
section below.

# Simple Setup for multiple SOCKS configs for firefox

Create a folder for your configs and startup scripts. Can be the same place as
this code. That path you will use below. For reference this text uses
`/Users/jonny/vpntabs`

For each VPN you want to run, you will download your wireguard config and name
it appropriately (e.g. `ProtonUS.adblock.server.conf`) and then create two new
files from those below with similar names (e.g. `ProtonUS.adblock.conf` and
`ProtonUS.adblock.sh`)

You will also create a launch script, the reference below is only for macOS. The
naming should also be similar (e.g.
`/Users/jonny/Library/LaunchAgents/com.ProtonUS.adblock.plist`)

## Config File

Make sure you use a unique port for every separate server
I recommend you set proxy authentication, you can use the same user/pass for all

```ini
# Link to the Downloaded config
WGConfig = /Users/jonny/vpntabs/ProtonUS.adblock.server.conf

# Used for firefox containers
[Socks5]
BindAddress = 127.0.0.1:25344 # Update the port here for each new server

# Socks5 authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...
```

## Startup Script File

This is a bash script to facilitate startup, not strictly essential, but adds
ease.
Note, you MUST update the first path to wherever you installed this code to.
Make sure you use the path for the config file above, not the one you downloaded
from e.g. protonvpn.

```bash
#!/bin/bash
/Users/jonny/wireproxy/wireproxy -c /Users/jonny/vpntabs/ProtonUS.adblock.conf
```

## MacOS LaunchAgent

To make it run every time you start your computer, you can create a launch agent
in `$HOME/Library/LaunchAgents`. Name reference above.

That file should contain the following, the label should be the same as the file
name and the paths should be set correctly:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ProtonUS.adblock</string>
    <key>Program</key>
    <string>/Users/jonny/vpntabs/ProtonUS.adblock.sh</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

To enable it, run
`launchctl load ~/Library/LaunchAgents/com.ProtonUS.adblock.plist` and
`launchtl start ~/Library/LaunchAgents/com.PortonUS.adblock.plist`

# Firefox Setup

You will need to enable the Multi Account Container Tabs extension and a proxy extension, I
recommend Sideberry, but Container Proxy also works.

Create a container to be dedicated to this VPN, and then add the IP, port,
username, and password from above.
