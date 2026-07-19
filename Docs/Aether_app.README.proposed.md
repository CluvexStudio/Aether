# Proposed README for `noob-coder-clude/Aether_app`

# Aether Android + Termux Companion

**فارسی** · **English**

This repository can serve two practical use-cases for Aether users:

1. **Android APK** for users who want a native app experience
2. **Termux Web Dashboard** for users who prefer running the Aether core locally in Termux and controlling it from a browser

---

## English

### Overview
`Aether_app` should not only publish the Android APK, but also ship the Termux companion assets in Releases so users can install and manage Aether from inside Termux with a browser-based UI.

This is especially useful for users who:
- already use Termux as their main environment
- want to keep the original Aether binary workflow
- prefer a visual dashboard instead of memorizing CLI flags
- need a simple update path when this repository is a fork of the original project

### What Releases should contain

#### Android assets
- `app-release.apk`

#### Termux assets
- `aether-web-install.sh`
- `aether-web-install.sh.sha256`
- `aether-termux-webapp.tar.gz`
- `aether-termux-webapp.tar.gz.sha256`

---

## Fast Termux install

### One-file bootstrap
```bash
chmod +x aether-web-install.sh
./aether-web-install.sh
```

This installer downloads the proper dashboard source, installs it into Termux, and opens an interactive menu.

### Manual archive install
```bash
tar -xzf aether-termux-webapp.tar.gz
cd termux-webapp
chmod +x install.sh
./install.sh
```

---

## What the Termux menu can do

After installation, the user runs:

```bash
aether-web
```

The interactive menu supports **Persian and English** and can:
- start the dashboard locally and auto-open the browser
- start the dashboard on LAN / Wi-Fi and auto-open the browser
- install the Aether core
- update the Aether core from the detected **original/main repo**
- update the dashboard itself from the **current fork/repo**
- show core status and active sources
- switch language between Persian and English

---

## Ports

- **Aether SOCKS5 proxy:** `127.0.0.1:1819`
- **Web dashboard UI:** `127.0.0.1:8787`

Why not use `1819` for the panel too?
Because `1819` belongs to Aether itself. The dashboard intentionally uses `8787` to avoid conflicting with the SOCKS5 proxy.

---

## Fork-aware update behavior

If this repository is a fork, the installer can detect the parent/original repository automatically.

That means by default:
- **dashboard updates** come from the current fork/repo
- **Aether core updates** come from the detected original/main repo

This is exactly the right behavior for maintaining a customized UI while still tracking the upstream Aether core.

---

## Recommended Release Notes section

### Termux Companion
This release also includes Termux assets for users who want a browser-based dashboard on top of the original Aether CLI core.

Included files:
- `aether-web-install.sh`
- `aether-web-install.sh.sha256`
- `aether-termux-webapp.tar.gz`
- `aether-termux-webapp.tar.gz.sha256`

Quick install in Termux:

```bash
chmod +x aether-web-install.sh
./aether-web-install.sh
```

After installation run:

```bash
aether-web
```

---

## فارسی

### خلاصه
بهتره ریپوی `Aether_app` فقط APK اندروید منتشر نکند، بلکه فایل‌های همراه **Termux Web Dashboard** را هم داخل Releases بگذارد تا کاربر بتواند از داخل ترموکس، Aether را با یک UI مرورگری مدیریت کند.

این مدل برای کاربرهایی خوبه که:
- Termux را محیط اصلی خودشان می‌دانند
- می‌خواهند از همان هسته اصلی Aether استفاده کنند
- دوست دارند به‌جای حفظ کردن فلگ‌ها، با منو و پنل جلو بروند
- می‌خواهند وقتی این ریپو fork است، آپدیت هسته از ریپوی اصلی بیاید

### فایل‌هایی که باید در Releases باشند

#### فایل اندروید
- `app-release.apk`

#### فایل‌های Termux
- `aether-web-install.sh`
- `aether-web-install.sh.sha256`
- `aether-termux-webapp.tar.gz`
- `aether-termux-webapp.tar.gz.sha256`

---

## نصب سریع روی Termux

### روش تک‌فایلی
```bash
chmod +x aether-web-install.sh
./aether-web-install.sh
```

### روش دستی با آرشیو کامل
```bash
tar -xzf aether-termux-webapp.tar.gz
cd termux-webapp
chmod +x install.sh
./install.sh
```

---

## منوی Termux چه کارهایی می‌کند؟

بعد از نصب:

```bash
aether-web
```

منوی تعاملی **فارسی / English** باز می‌شود و می‌تواند:
- داشبورد را لوکال اجرا کند و مرورگر را خودکار باز کند
- داشبورد را روی LAN / Wi-Fi اجرا کند و مرورگر را خودکار باز کند
- هسته Aether را نصب کند
- هسته Aether را از **ریپوی اصلی** آپدیت کند
- خود داشبورد را از **فورک / ریپوی فعلی** آپدیت کند
- وضعیت هسته و سورس‌ها را نشان دهد
- زبان را بین فارسی و انگلیسی عوض کند

---

## پورت‌ها

- **پراکسی SOCKS5 خود Aether:** `127.0.0.1:1819`
- **پنل وب:** `127.0.0.1:8787`

دلیل اینکه پنل روی `1819` نیست این است که آن پورت متعلق به خود Aether است. برای جلوگیری از تداخل، UI روی `8787` اجرا می‌شود.

---

## رفتار آپدیت در حالت fork

اگر این ریپو fork باشد، نصاب می‌تواند ریپوی والد/اصلی را تشخیص بدهد.

در نتیجه به‌صورت پیش‌فرض:
- **آپدیت داشبورد** از همین فورک/ریپو می‌آید
- **آپدیت هسته Aether** از ریپوی اصلی می‌آید

این رفتار برای نگه داشتن UI سفارشی و در عین حال دنبال کردن هسته upstream، بهترین حالت است.
