# Run Aether on an OpenWrt router

Aether connects to Cloudflare WARP and offers that connection as a local proxy. On Android, [PattNG](https://github.com/patterniha/PattNG) already does this. This guide does the same thing on a router, and starts it on boot.

When you finish, Aether listens at `127.0.0.1:1819`. Point a proxy client on the router at that address and its traffic goes through WARP. A test from the router prints `warp=on`.


## What you need

- An OpenWrt router you can log into as root over SSH.
- A Linux PC to build Aether. The router is too small to build it. Install Rust 1.98 or newer on the PC.
- If Aether has run on this router before, leave `/etc/aether` in place. Those files are this device’s Cloudflare login. Deleting them makes Cloudflare treat it as a new device.

This guide is written for a common 32-bit ARM router. Check yours before building.

## Check the router

```bash
ssh root@ROUTER
uname -m
ls /lib/ld-musl*.so*
```

`uname -m` should print `armv7l`, and the second command should find a file. Then follow the build as written.

`aarch64` and `x86_64` also work, but every `armv7` name in the build commands has to be changed to match. MIPS routers are not supported.


## Download 

Get the sutable build for your platform from: https://github.com/CluvexStudio/Aether/releases/

## Copy it to the router

Leave `/etc/aether` alone if it is already there.

```bash
scp target/armv7-unknown-linux-musleabihf/release/aether root@ROUTER:/tmp/aether-new

ssh root@ROUTER
cp -a /usr/bin/aether /usr/bin/aether.prev 2>/dev/null || true
mv /tmp/aether-new /usr/bin/aether
chmod 755 /usr/bin/aether
/usr/bin/aether -v
/usr/bin/aether help | grep masque-sni
```

The help text must include `--masque-sni`. 

## Run it and save configuration

```sh
mkdir -p /etc/aether
aether --config /etc/aether/aether.toml
```

## Start it on boot

Save this as `/etc/init.d/aether`. 

```sh
nano /etc/init.d/aether
```

Paste this:

```sh
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=10

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/aether \
        --config /etc/aether/aether.toml \
        --perf low \
        --protocol masque \
        --scan balanced \
        --ip v4 \
        --masque-sni www.cloudflare.com \
        --h2 \
        --tls-ciphers 'ALL:!aPSK:!ECDSA+SHA1:!3DES' \
        --bind 127.0.0.1:1819 \
        --mark 255 \
        --quick-reconnect
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

Turn it on:

```bash
chmod 755 /etc/init.d/aether
/etc/init.d/aether enable
/etc/init.d/aether restart
```

## Check that it works

On the router:

```bash
logread -e aether | tail -30
curl -sS -m 20 -x socks5h://127.0.0.1:1819 \
  https://www.cloudflare.com/cdn-cgi/trace
```

A good log looks like this:

```text
[h2] tls established
[h2] connect-ip status: 200
[h2] tunnel validated (end-to-end data confirmed); exposing socks5
[+] socks5 server listening on 127.0.0.1:1819
```

The trace output should contain `warp=on`. That means the test went through WARP.

To use it, set a SOCKS proxy to `127.0.0.1`, port `1819`. In PassWall, add a SOCKS node with that address and choose it for the traffic you want to send through WARP.

Restart later with:

```bash
/etc/init.d/aether restart
```

## Add to passwall

In Passwall2 create a SOCKS5 node ponting to 127.0.0.1:1819 and name it aether.
Create a shunt and use aether as default node.
