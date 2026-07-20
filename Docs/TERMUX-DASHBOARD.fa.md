# راهنمای قطعی داشبورد Aether در Termux

این فایل برای وقتی است که اینترنت خراب است و حوصلهٔ آزمون‌وخطای زیاد نداری. اینجا همهٔ دستورهای مهم برای نصب، اجرا، آپدیت و عیب‌یابی داشبورد Aether داخل Termux یک‌جا آمده است.

---

## فرق دو پورت مهم

- **پورت خود Aether / پراکسی SOCKS5:** `127.0.0.1:1819`
- **پورت پنل وب داشبورد:** `127.0.0.1:8787`

> این دو تا عمداً جدا هستند. اگر هر دو را یکی کنی، پنل و پراکسی با هم تداخل می‌کنند.

---

## نصب سریع داشبورد از روی GitHub

### روش پیشنهادی

```bash
curl -fsSL https://raw.githubusercontent.com/noob-coder-clude/Aether/arena/019f7b56-aether/termux-webapp/bootstrap-install.sh -o aether-web-install.sh && chmod +x aether-web-install.sh && ./aether-web-install.sh
```

اگر raw روی شبکه‌ات مشکل داشت، از روش tarball استفاده کن:

```bash
pkg update -y && pkg install -y curl tar python git && \
TMP=$(mktemp -d) && cd "$TMP" && \
curl -L -H 'Accept: application/vnd.github+json' \
https://api.github.com/repos/noob-coder-clude/Aether/tarball/arena/019f7b56-aether \
-o aether-web.tar.gz && \
mkdir src && tar -xzf aether-web.tar.gz -C src && \
cd "$(find src -maxdepth 2 -type d -name termux-webapp | head -n1)" && \
chmod +x install.sh && \
AETHER_WEB_REPO=noob-coder-clude/Aether \
AETHER_WEB_REF=arena/019f7b56-aether \
./install.sh
```

---

## آدرس پنل بعد از نصب

داشبورد را در مرورگر باز کن:

```text
http://127.0.0.1:8787
```

اگر از خود پنل PWA نصب کردی و نسخه قدیمی نشان داد، یک بار این را امتحان کن:

```text
http://127.0.0.1:8787/?v=latest
```

---

## فایل تنظیم سورس‌ها

گاهی لازم است منبع آپدیت را دستی درست کنی تا `update-panel` به branch درست اشاره کند.

```bash
mkdir -p ~/.config/aether-web && cat > ~/.config/aether-web/sources.conf <<'EOF'
AETHER_WEB_REPO=noob-coder-clude/Aether
AETHER_WEB_REF=arena/019f7b56-aether
AETHER_CORE_REPO=CluvexStudio/Aether
AETHER_WEB_LANG=fa
AETHER_PANEL_PORT=8787
EOF
```

این فایل تعیین می‌کند:
- پنل از کدام repo/branch خودش را آپدیت کند
- هسته Aether از کدام repo آپدیت شود
- زبان پیش‌فرض چیست
- پنل روی چه پورتی اجرا شود

---

## منوی تعاملی

برای باز کردن منوی ترموکس:

```bash
aether-web
```

این منو برای نصب و کنترل سریع طراحی شده است.

---

## دستورهای اصلی Termux

### 1) اجرای پنل روی خود گوشی

```bash
aether-web start
```

**چه می‌کند؟**
- داشبورد را روی `127.0.0.1:8787` اجرا می‌کند
- تلاش می‌کند مرورگر را هم باز کند

---

### 2) اجرای پنل برای دسترسی از لپ‌تاپ / دستگاه دیگر

```bash
aether-web lan
```

**چه می‌کند؟**
- داشبورد را روی LAN باز می‌کند
- مناسب وقتی است که می‌خواهی از دستگاه دیگری در همان وای‌فای پنل را ببینی

> فقط روی شبکهٔ محلی مطمئن استفاده کن.

---

### 3) توقف پنل

```bash
aether-web stop
```

**چه می‌کند؟**
- فقط خود پنل وب را می‌بندد
- لزوماً خود تونل Aether را kill نمی‌کند مگر اینکه خودت هم Stop بزنی

---

### 4) باز کردن پنل اگر در حال اجراست

```bash
aether-web open
```

**چه می‌کند؟**
- اگر پنل بالا باشد، مرورگر را روی همان آدرس باز می‌کند

---

### 5) وضعیت پنل

```bash
aether-web status
```

**چه می‌کند؟**
- می‌گوید پنل اجرا هست یا نه
- PID، آدرس‌ها و لاگ پنل را نشان می‌دهد

---

### 6) نصب هسته Aether

```bash
aether-web install-core
```

**چه می‌کند؟**
- باینری اصلی `aether` را برای معماری گوشی دانلود و نصب می‌کند
- معمولاً داخل `$PREFIX/bin/aether`

---

### 7) آپدیت هسته Aether

```bash
aether-web update-core
```

**چه می‌کند؟**
- هسته Aether را از ریپوی اصلی آپدیت می‌کند
- برای وقتی است که خود core تغییر کرده ولی پنل را نمی‌خواهی دست بزنی

---

### 8) وضعیت هسته Aether

```bash
aether-web core-status
```

**چه می‌کند؟**
- مسیر باینری و نسخهٔ نصب‌شدهٔ هسته را نشان می‌دهد

---

### 9) حذف هسته Aether

```bash
aether-web remove-core
```

**چه می‌کند؟**
- خود باینری Aether را حذف می‌کند
- پنل را پاک نمی‌کند

---

### 10) آپدیت خود پنل

```bash
aether-web update-panel
```

**چه می‌کند؟**
- فقط خود داشبورد و فایل‌های UI/اسکریپت‌ها را آپدیت می‌کند
- ممکن است چند ثانیه پنل قطع شود
- معمولاً خود تونل اصلی را قطع نمی‌کند، اما بهتر است وسط کار خیلی حساس انجامش ندهی

---

### 11) تغییر زبان منو

```bash
aether-web lang
```

**چه می‌کند؟**
- زبان منوی تعاملی ترموکس را بین فارسی و انگلیسی عوض می‌کند

---

### 12) حذف کامل پنل

```bash
aether-web uninstall
```

**چه می‌کند؟**
- فایل‌های داشبورد Aether Web را از ترموکس حذف می‌کند

---

## روال پیشنهادی استفاده

### نصب اولیه

```bash
aether-web install-core
aether-web start
```

بعد در مرورگر:

```text
http://127.0.0.1:8787
```

---

## اگر پنل آپدیت نشد یا امکانات جدید را ندیدی

1. فایل `sources.conf` را درست کن
2. این را بزن:

```bash
aether-web update-panel
```

3. اگر لازم شد:

```bash
aether-web stop
aether-web start
```

4. صفحه را با آدرس زیر باز کن تا کش قدیمی دور زده شود:

```text
http://127.0.0.1:8787/?v=latest
```

---

## اگر پنل بالا می‌آید ولی هنوز چیزهای جدید را نمی‌بینی

این را چک کن:

```bash
grep -n 'smartConnectBtn\|detectIpBtn\|speedTestBtn\|copySocksBtn\|runSiteChecksBtn' $PREFIX/opt/aether-web/static/index.html
```

اگر چیزی برنگرداند:
- هنوز نسخه جدید واقعاً نصب نشده

اگر خروجی داد:
- فایل‌ها نصب شده‌اند
- مشکل از کش مرورگر/PWA است

---

## اگر اینترنت افتضاح بود و خواستی حداقل پنل را تمیز بالا بیاوری

### نصب تمیز و کامل

```bash
aether-web stop 2>/dev/null || true
rm -rf $PREFIX/opt/aether-web

pkg update -y && pkg install -y curl tar python git && \
TMP=$(mktemp -d) && cd "$TMP" && \
curl -L -H 'Accept: application/vnd.github+json' \
https://api.github.com/repos/noob-coder-clude/Aether/tarball/arena/019f7b56-aether \
-o aether-web.tar.gz && \
mkdir src && tar -xzf aether-web.tar.gz -C src && \
cd "$(find src -maxdepth 2 -type d -name termux-webapp | head -n1)" && \
chmod +x install.sh && \
AETHER_WEB_REPO=noob-coder-clude/Aether \
AETHER_WEB_REF=arena/019f7b56-aether \
./install.sh
```

بعد:

```bash
aether-web start
```

---

## اگر خود Aether وصل نمی‌شد

### حالت‌های پیشنهادی داخل پنل

به‌ترتیب این‌ها را تست کن:

1. **MASQUE + h2 + fragment + ironclad**
2. **MASQUE + h2 + gfw**
3. **WireGuard + aggressive**
4. **GOOL + aggressive**

---

## درباره VPN سیستم

- برای **اجرای واقعی Aether** بهتره VPN سیستم **خاموش** باشد
- برای **دانلود / آپدیت** اگر لازم شد می‌توانی موقتاً VPN را روشن کنی

---

## اگر می‌خواهی فایل‌های مهم را بشناسی

### فایل تنظیمات داشبورد

```text
~/.config/aether-web/config.json
```

### فایل وضعیت پنل

```text
~/.config/aether-web/state.json
```

### لاگ Aether

```text
~/.config/aether-web/aether.log
```

### تنظیمات سورس‌ها

```text
~/.config/aether-web/sources.conf
```

---

## خلاصهٔ خیلی کوتاه

### نصب

```bash
./aether-web-install.sh
```

### اجرای پنل

```bash
aether-web start
```

### نصب هسته

```bash
aether-web install-core
```

### آپدیت هسته

```bash
aether-web update-core
```

### آپدیت پنل

```bash
aether-web update-panel
```

### باز کردن پنل

```bash
aether-web open
```

### آدرس پنل

```text
http://127.0.0.1:8787
```

### پورت پراکسی Aether

```text
127.0.0.1:1819
```
