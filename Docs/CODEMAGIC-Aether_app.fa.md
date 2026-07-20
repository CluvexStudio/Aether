# راه‌اندازی Codemagic برای `Aether_app`

این راهنما برای وقتی است که می‌خواهی **بدون Colab و بدون GitHub Actions** فایل APK را از روی `Aether_app` بسازی و از روی گوشی دانلود کنی.

> واقعیت مهم: من به ریپوی `Aether_app` دسترسی نوشتن ندارم، برای همین نتوانستم فایل را مستقیم آنجا کامیت کنم. اما فایل آماده را در همین ریپو گذاشته‌ام تا فقط **یک فایل** را به ریشهٔ `Aether_app` منتقل کنی و build را شروع کنی.

---

## فایل آماده

فایل آمادهٔ Codemagic اینجاست:

- `Docs/Aether_app.codemagic.yaml`

این فایل باید داخل ریپوی `Aether_app` با نام زیر قرار بگیرد:

```text
codemagic.yaml
```

---

## سریع‌ترین روش بدون اعصاب‌خردی

### روش پیشنهادی
1. از داخل GitHub ریپوی `Aether_app` را باز کن.
2. در ریشهٔ repo روی **Add file** بزن.
3. روی **Upload files** بزن.
4. فایل `Docs/Aether_app.codemagic.yaml` را از این ریپو دانلود کن.
5. اسمش را موقع آپلود یا قبل از آپلود بگذار:

```text
codemagic.yaml
```

6. Commit changes
7. برگرد به Codemagic
8. Detect configuration from `codemagic.yaml`
9. Build را اجرا کن

---

## اگر بخواهی از خود گوشی انجام بدهی

### قدم 1: فایل yaml را دانلود کن
اگر raw لینک در دسترس بود، این را روی گوشی باز کن:

```text
https://raw.githubusercontent.com/noob-coder-clude/Aether/arena/019f7b56-aether/Docs/Aether_app.codemagic.yaml
```

اگر raw مشکل داشت، از خود GitHub فایل را باز کن و **Download raw file** یا **View raw** بزن.

### قدم 2: اسم فایل را عوض کن
اسم نهایی باید این باشد:

```text
codemagic.yaml
```

### قدم 3: در `Aether_app` آپلود کن
در ریشهٔ repo `Aether_app` آپلودش کن.

---

## داخل Codemagic چی انتخاب کنم؟

بعد از اینکه فایل را در `Aether_app` گذاشتی:

1. برو Codemagic
2. پروژه `Aether_app` را باز کن
3. Workflow از `codemagic.yaml` را انتخاب کن
4. اگر خواست Environment را چک کنی، همین‌ها باید باشند:
   - Flutter 3.22.0
   - Java 17
5. Build را بزن

---

## خروجی build کجاست؟

بعد از build موفق، داخل Codemagic در بخش **Artifacts** این فایل‌ها را می‌بینی:

```text
app-arm64-v8a-release.apk
app-armeabi-v7a-release.apk
app-x86_64-release.apk
```

### برای بیشتر گوشی‌ها
این فایل را دانلود کن:

```text
app-arm64-v8a-release.apk
```

---

## بدون کابل چطور APK را روی گوشی بگیرم؟

### ساده‌ترین راه
- از خود گوشی وارد Codemagic شو
- Build را باز کن
- Artifacts را دانلود کن

### اگر خواستی حرفه‌ای‌تر
بعداً می‌توانی Codemagic را به این‌ها وصل کنی:
- GitHub Releases
- Firebase App Distribution

اما برای شروع، **Artifacts خود Codemagic کافی است**.

---

## اگر build fail شد چه کار کنم؟

وقتی build fail شد:

1. وارد build log شو
2. 100 تا 200 خط آخر را کپی کن
3. همینجا بفرست

من از روی log دقیق می‌گم:
- کدام dependency خراب است
- کدام فایل باید عوض شود
- یا کدام مرحلهٔ build باید اصلاح شود

---

## چرا این روش بهتر از Colab است؟

چون:
- پایدارتر است
- environment تکرارپذیرتر است
- artifact واقعی می‌دهد
- از روی گوشی هم قابل دانلود است
- مخصوص build اپ موبایل است

---

## اگر خواستی فقط یک بار خیلی تمیز انجام دهی

### چک‌لیست نهایی
- [ ] فایل `codemagic.yaml` در ریشهٔ `Aether_app` گذاشته شد
- [ ] Codemagic به `Aether_app` وصل است
- [ ] Workflow از YAML شناسایی شده
- [ ] Build اجرا شده
- [ ] از بخش Artifacts فایل `app-arm64-v8a-release.apk` گرفته شد

---

## جمع‌بندی کوتاه

### کاری که الان باید بکنی
فقط این فایل را ببر به `Aether_app`:

```text
Docs/Aether_app.codemagic.yaml
```

و آنجا اسمش را بگذار:

```text
codemagic.yaml
```

بعد build را از Codemagic بزن.

اگر خطا داد، لاگ را بفرست.
