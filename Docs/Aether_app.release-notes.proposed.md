# Proposed release notes snippet for `noob-coder-clude/Aether_app`

## Termux Companion Assets

This release also includes a Termux-friendly browser dashboard for Aether.

### Included files
- `aether-web-install.sh`
- `aether-web-install.sh.sha256`
- `aether-termux-webapp.tar.gz`
- `aether-termux-webapp.tar.gz.sha256`

### Quick install in Termux
```bash
chmod +x aether-web-install.sh
./aether-web-install.sh
```

### What it does
- installs a local browser dashboard for Aether on Termux
- keeps the Aether SOCKS5 proxy on `127.0.0.1:1819`
- opens the web UI on `127.0.0.1:8787`
- provides a Persian / English interactive menu
- can update the Aether core from the original/main repo when this repository is a fork
- can update the dashboard itself from the current fork/repo

### After install
Run:
```bash
aether-web
```
