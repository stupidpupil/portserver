# portserver

A single-file server for sharing MacPorts binary archives to other machines. It handles signing archives on-the-fly.

> [!CAUTION]
> This project includes code produced with a "generative AI". This is documented here for transparency.

See [_Sharing Archives under MacPorts 2_ on the MacPorts wiki](https://trac.macports.org/wiki/howto/ShareArchives2) for a general overview of the task.

## Install

0. Edit `/opt/local/etc/macports/macports.conf` to include `portimage_mode directory_and_archive`

1. Copy _portserver.py_ to `/opt/local/bin/portserver.py` and `chmod a=rx /opt/local/bin/portserver.py`

2. Copy _org.github.portserver.plist_ to `/Library/LaunchDaemons/org.github.portserver.plist`.

3. `sudo launchctl load /Library/LaunchDaemons/org.github.portserver.plist`

4. `sudo launchctl kickstart -k org.github.portserver`.

## Configure client

Assuming the server has the Bonjour/Zeroconf hostname `Spektr.local`:

1. `curl http://Spektr.local:6227/pubkey.pem -o /opt/local/share/macports/keys/archives/spektr-local-pub.pem`

2. Add `/opt/local/share/macports/keys/archives/spektr-local-pub.pem` to `/opt/local/etc/macports/pubkeys.conf`

3. Add the following to `/opt/local/etc/macports/archive_sites.conf`

```
name    Spektr.local
urls    http://Spektr.local:6227/
```

## Security

Probably terrible.
