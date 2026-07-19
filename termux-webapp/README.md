# Aether Termux Web

A polished local web dashboard for running **Aether** on **Termux** and controlling it from your browser.

It is designed for users who prefer a visual panel instead of manually typing commands every time.

## What it can do

- Install / update / uninstall the Aether Termux binary from GitHub Releases
- Start, stop, and restart Aether from the browser
- Show live status, PID, uptime, binary version, and the exact launch command
- Save your preferred profile locally
- Ready-made presets for:
  - MASQUE recommended
  - UDP blocked / HTTP2
  - strict DPI / fragmentation
  - fast WireGuard
  - stable GOOL
- Live log viewer
- One-click proxy test using `curl` through `socks5h://127.0.0.1:1819`
- Built-in Persian-first help and troubleshooting

## Install in Termux

Extract the release asset, then run:

```bash
cd termux-webapp
chmod +x install.sh
./install.sh
```

After installation:

```bash
aether-web
```

Open:

```text
http://127.0.0.1:8787
```

## Optional: open from another device on the same Wi-Fi

```bash
aether-web --host 0.0.0.0 --port 8787
```

Then open the shown local IP in your browser.

> Only do this on a trusted LAN.

## Files written at runtime

The dashboard stores its runtime files here:

```text
~/.config/aether-web/
```

Main files:

- `config.json` — saved dashboard settings
- `state.json` — current runtime state / PID
- `aether.log` — Aether output log

## Quick flow

1. Open the dashboard.
2. Click **Install Aether** once.
3. Pick a preset or edit the settings manually.
4. Click **Save settings**.
5. Click **Start Aether**.
6. Set your browser/system proxy to `127.0.0.1:1819`.
7. Use the built-in **Proxy Test** button to verify traffic.

## Notes

- The dashboard does **not** replace the Aether engine; it manages the normal CLI binary.
- The Aether SOCKS5 proxy inside the UI stays on `127.0.0.1:1819` by default.
- The web panel intentionally runs on `8787` so it does not conflict with Aether itself.
- If the current repo is a fork, the installer tries to detect the parent repo and uses that as the default core-update source.

## Included docs

See the `docs/` folder inside this package:

- `guide.fa.md`
- `guide.en.md`
