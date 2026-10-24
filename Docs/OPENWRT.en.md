# Run Aether on an OpenWrt router

Aether connects to Cloudflare WARP and offers that connection as a local proxy. On Android, [PattNG](https://github.com/patterniha/PattNG) already does this. This guide does the same thing on a router, and starts it on boot.

When you finish, Aether listens at `127.0.0.1:1819`. Point a proxy client on the router at that address and its traffic goes through WARP. A test from the router prints `warp=on`.

The rest of the router stays as it is. Only programs you point at this proxy use Aether.

The short install on the [README](../README.md#openwrt) downloads a release binary and runs it once. Use this page when you want a service, and when that binary is too old to set the server name below.

## Why the usual install fails

A release whose help text does not list `--masque-sni`, including v2.3.0, cannot use the address that still works, `www.cloudflare.com`. Those builds try `consumer-masque.cloudflareclient.com`, and many networks block that name. The connection then sits there and the proxy never opens. Build the current source instead. A newer release is fine once `aether help` shows `--masque-sni`.

WireGuard on UDP port 4500 is a different connection. Where it is blocked, Aether waits and then stops with `verify timeout`. Use the same connection the phone uses, on port 443.

If you copy the phone’s command, leave out `--upstream`. That address exists only inside PattNG.

The proxy has no password. Keep it on `127.0.0.1`, so only the router itself can use it.

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

## Build it on the PC

Clone the current source. A v2.3.0 download will not work.

```bash
git clone https://github.com/CluvexStudio/Aether.git
cd Aether/aether

sudo apt-get update
sudo apt-get install -y build-essential clang cmake ninja-build curl rsync

rustup update stable
rustup target add armv7-unknown-linux-musleabihf
```

OpenWrt needs its own compiler. Install it with:

```bash
sudo mkdir -p /opt/musl-cross
curl -fL -o /tmp/musl-cross.tar.xz \
  https://github.com/AmanoTeam/musl-gcc-cross/releases/download/gcc-15/x86_64-unknown-linux-gnu.tar.xz
sudo tar -C /opt/musl-cross --strip-components=1 -xJf /tmp/musl-cross.tar.xz
/opt/musl-cross/bin/armv7-unknown-linux-musleabihf-gcc --version
```

The build also needs a few Linux header files next to that compiler:

```bash
curl -fL -o /tmp/linux.tar.xz \
  https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
mkdir -p /tmp/ksrc
tar -C /tmp/ksrc --strip-components=1 -xf /tmp/linux.tar.xz
make -s -C /tmp/ksrc ARCH=arm INSTALL_HDR_PATH=/tmp/hdr-arm headers_install
sudo cp -rn /tmp/hdr-arm/include/. \
  /opt/musl-cross/armv7-unknown-linux-musleabihf/include/
ls /opt/musl-cross/armv7-unknown-linux-musleabihf/include/linux/random.h
```

Then build:

```bash
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=/opt/musl-cross/bin/armv7-unknown-linux-musleabihf-gcc
export CC_armv7_unknown_linux_musleabihf=/opt/musl-cross/bin/armv7-unknown-linux-musleabihf-gcc
export CXX_armv7_unknown_linux_musleabihf=/opt/musl-cross/bin/armv7-unknown-linux-musleabihf-g++
export AR_armv7_unknown_linux_musleabihf=/opt/musl-cross/bin/armv7-unknown-linux-musleabihf-ar
export BINDGEN_EXTRA_CLANG_ARGS_armv7_unknown_linux_musleabihf="--target=armv7-unknown-linux-musleabihf --sysroot=/opt/musl-cross/armv7-unknown-linux-musleabihf"
export RUSTFLAGS="--cfg libc_unstable_musl_v1_2_3"

cargo build --release --target armv7-unknown-linux-musleabihf
file target/armv7-unknown-linux-musleabihf/release/aether
```

`file` should say the result is an ARM program, statically linked. The router then needs no extra libraries.

If the build says it cannot find libclang, point it at that library and run the build again:

```bash
export LIBCLANG_PATH="$(dirname "$(gcc -print-file-name=libclang.so 2>/dev/null || echo /usr/lib/llvm-21/lib/libclang.so)")"
```

Use the folder on your PC that actually contains `libclang.so`.

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

The help text must include `--masque-sni`. If it does not, the router is still running the old download. Copy the program you just built.

## Start it on boot

Save this as `/etc/init.d/aether`. It is the phone’s command, with a few router changes: listen on port 1819, keep the login files in `/etc/aether`, use less memory, and leave out the phone-only `--upstream` line.

`--mark 255` is the same mark as `0xff` in the [firewall mark](DOCS.en.md#firewall-mark) section. PassWall already lets that mark out. If the router sends its own traffic into a tun, add the `ip rule` from that section as well.

The address in `--peer` is the one PattNG saved. If your phone profile names a different address, use that one in both places below.

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
        --peer 162.159.198.41:443 \
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

The phone’s command looks like this:

```text
aether --bind 127.0.0.1:10819 \
  --protocol masque --scan balanced --ip v4 \
  --masque-sni www.cloudflare.com --h2 \
  --tls-ciphers 'ALL:!aPSK:!ECDSA+SHA1:!3DES' \
  --peer 162.159.198.41:443 --quick-reconnect \
  --upstream socks5://127.0.0.1:10822
```

The phone listens on port 10819 and adds `--upstream`, which keeps the app from catching its own traffic. The router does not need that line. Port 1819 is Aether’s usual port. Another free port is fine if you use the same one everywhere below.

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

## If it does not start

`unknown option '--masque-sni'` means the router is running a release that does not have the option yet. Install the program you built.

If the log stays on `[h2] connecting tcp` and never says `tls established`, the service is missing `--masque-sni www.cloudflare.com` or `--h2`.

You can test the address itself from the router:

```bash
curl -sv -m 8 --resolve www.cloudflare.com:443:162.159.198.41 \
  https://www.cloudflare.com/ -o /dev/null
```

A certificate warning here is normal. Aether does not care about the certificate name. The connection has to finish, rather than hang until it times out.

`verify timeout` means the service is still on WireGuard. Replace it with the service file above.
