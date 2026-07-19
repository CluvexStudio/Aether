# Proposed README for `noob-coder-clude/Aether_app`

# Aether Android + Termux Companion

**فارسی** · **English**

This repository can ship two user-facing ways to use Aether:

1. **Android APK** built from Flutter/Kotlin
2. **Termux Web Dashboard** assets for users who prefer running the Aether core locally in Termux and controlling it from a browser

---

## What should be included in Releases

### Android assets
- `app-release.apk`

### Termux companion assets
- `aether-web-install.sh`
- `aether-web-install.sh.sha256`
- `aether-termux-webapp.tar.gz`
- `aether-termux-webapp.tar.gz.sha256`

---

## Fast Termux install

```bash
chmod +x aether-web-install.sh
./aether-web-install.sh
```

The installer opens an interactive Persian/English menu after installation.

### What the menu can do
- start the dashboard locally and open the browser automatically
- start the dashboard on LAN/Wi-Fi and open the browser automatically
- install the Aether core
- update the Aether core from the original/main repo
- update the dashboard itself from the current fork/repo
- show status and active sources

### Ports
- Aether SOCKS5 proxy: `127.0.0.1:1819`
- Web dashboard UI: `127.0.0.1:8787`

The UI intentionally uses `8787` so it does not conflict with Aether's SOCKS5 port `1819`.

---

## Manual Termux install

```bash
tar -xzf aether-termux-webapp.tar.gz
cd termux-webapp
chmod +x install.sh
./install.sh
```

---

## Notes for fork-based maintenance

If this repository is a fork, the Termux installer can detect the parent/original repo and use that as the default update source for the Aether core.

That means:
- **dashboard updates** come from the current repo/fork
- **Aether core updates** come from the detected original repo by default

---

## Persian summary

این ریپو بهتر است علاوه بر APK اندروید، فایل‌های همراه Termux را هم داخل Releases منتشر کند تا کاربرها بتوانند بدون دردسر از داخل ترموکس پنل وب را نصب کنند.

فایل‌های لازم برای Release:
- `aether-web-install.sh`
- `aether-web-install.sh.sha256`
- `aether-termux-webapp.tar.gz`
- `aether-termux-webapp.tar.gz.sha256`

نصب سریع روی Termux:

```bash
chmod +x aether-web-install.sh
./aether-web-install.sh
```

بعد از نصب، منوی فارسی/انگلیسی باز می‌شود و کاربر می‌تواند:
- پنل را اجرا کند
- مرورگر را خودکار باز کند
- هسته Aether را نصب یا آپدیت کند
- خود پنل را از روی فورک فعلی آپدیت کند

پورت‌ها:
- پراکسی Aether: `127.0.0.1:1819`
- پنل وب: `127.0.0.1:8787`
