# Aether Termux Web Guide

This package provides a local web dashboard for managing Aether on Termux.

## Quick start

### 1) Install the dashboard
```bash
cd termux-webapp
chmod +x install.sh
./install.sh
```

### 2) Launch it
```bash
aether-web
```

### 3) Open it in your browser
```text
http://127.0.0.1:8787
```

## First use

1. In the `aether-web` menu, first choose **Install Aether core**.
2. Then choose **Start dashboard (local only)** so the browser opens automatically.
3. Pick a preset.
4. Start with **Iran / Recommended** for the default MASQUE setup.
5. If QUIC/UDP is blocked, use **UDP blocked**.
6. If the network is very strict, try **Strict DPI**.
7. Save your settings and click **Start Aether**.
8. Watch the live logs.

## Presets

### Iran / Recommended
- Protocol: MASQUE
- Transport: h3
- Noise: firewall
- Scan: balanced
- Best for: general first try

### UDP blocked
- Protocol: MASQUE
- Transport: h2
- Best for: networks where h3/QUIC does not connect

### Strict DPI
- Protocol: MASQUE
- Transport: h2
- Fragmentation: enabled
- Noise: gfw
- Best for: very aggressive filtering and TLS handshake blocking

### Fast WireGuard
- Protocol: wg
- Best for: speed on less restrictive networks

### Stable GOOL
- Protocol: gool
- Best for: when plain WireGuard connects but is unstable

## Proxy test

When running, the proxy should be available at:

```text
127.0.0.1:1819
```

Use the dashboard **Proxy Test** button or run manually:

```bash
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

## Browser proxy

If your browser allows a dedicated proxy configuration:

- Host: `127.0.0.1`
- Port: `1819`
- Type: `SOCKS5`
- Prefer DNS through the proxy (`socks5h`)

## Important options

### Protocol
- `masque`: recommended default
- `wg`: faster, less stealthy
- `gool`: nested and more resilient

### Scan mode
- `turbo`: fastest
- `balanced`: recommended
- `thorough`: deeper scan
- `stealth`: slower and quieter
- `ironclad`: strongest validation

### Quick reconnect
- `on`: reuse last known-good gateway first
- `off`: always rescan
- `ask`: keep the CLI-like behavior

### MASQUE transport
- `h3`: default and faster
- `h2`: use when UDP/QUIC is restricted

### Fragmentation
Only for h2. Turn it on when the TLS ClientHello itself is being blocked.

## Logs

Logs are stored at:

```text
~/.config/aether-web/aether.log
```

If the process starts but traffic still hangs, check the logs first.

## Troubleshooting

### Aether does not install
- Make sure Termux itself has internet access.
- Confirm GitHub is reachable on your network.
- Try Install or Update again.

### Start does nothing
- Check the binary path in the Advanced section.
- If you installed Aether manually, verify `aether --version` works.
- Review the logs.

### It connects but websites do not load
- Run **Proxy Test**.
- If you are on h3, try h2.
- If you are already on h2, enable fragmentation.
- Switch scan mode to `ironclad`.

### It keeps dropping
- Use a heavier noise profile.
- Switch from MASQUE to GOOL or WireGuard.
- Turn Quick reconnect to `on`.

## LAN mode

To open the dashboard from another device on the same Wi-Fi:

```bash
aether-web --host 0.0.0.0 --port 8787
```

Then open the phone's local IP in a browser.

> Only do this on a trusted network.
