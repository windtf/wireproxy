# Running wireproxy with systemd

If you're on a systemd-based distro, you'll most likely want to run Wireproxy as a systemd unit.

The provided systemd unit assumes you have the wireproxy executable installed on `/opt/wireproxy/wireproxy` and a configuration file stored at `/etc/wireproxy.conf`. These paths can be customized by editing the unit file.

# Setting up the unit

1. Copy the `wireproxy.service` file from this directory to `/etc/systemd/system/`, or use the following cURL command to download it:
   ```bash
   curl https://raw.githubusercontent.com/pufferffish/wireproxy/master/systemd/wireproxy.service | sudo tee /etc/systemd/system/wireproxy.service
   ```

2. If necessary, customize the unit.

   Edit the parts with `LoadCredential`, `ExecStartPre=` and `ExecStart=` to point to the executable and the configuration file. For example, if wireproxy is installed on `/usr/bin` and the configuration file is located in `/opt/myfiles/wireproxy.conf` do the following change:
   ```service
   LoadCredential=conf:/opt/myfiles/wireproxy.conf
   ExecStartPre=/usr/bin/wireproxy -n -c ${CREDENTIALS_DIRECTORY}/conf
   ExecStart=/usr/bin/wireproxy -c ${CREDENTIALS_DIRECTORY}/conf
   ```

4. Reload systemd and enable the unit.
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now wireproxy.service
   ```

5. Make sure it's working correctly.

   Finally, check out the unit status to confirm `wireproxy.service` has started without problems. You can use commands like `systemctl status wireproxy.service` and/or `sudo journalctl -u wireproxy.service`.

# Additional notes

If you want to disable the extensive logging that's done by Wireproxy, simply add `-s` parameter to `ExecStart=`. This will enable the silent mode that was implemented with [pull/67](https://github.com/pufferffish/wireproxy/pull/67).
