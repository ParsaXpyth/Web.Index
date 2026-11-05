# Web.Index

سایت دوزبانه‌ی (فارسی پیش‌فرض / English) Web.Index با پنل مدیریت ساده و امن، روی Cloudflare Workers.
Bilingual site with a simple secure admin panel on Cloudflare Workers + one KV store (no R2, no database setup).

## ساختار / Files
```
public/index.html   کل سایت / the whole public site
public/admin.html   صفحه ورود + پنل مدیریت (یک فایل) / login + dashboard in one file
src/worker.js       بک‌اند: ورود، رمز، آپلود، API / backend (password formula lives here)
src/credentials.js  نام کاربری + رمزِ رمزنگاری‌شده / username + password hash (separate file)
tools/hash.html     ساخت رمز رمزنگاری‌شده (آفلاین) / offline hash generator
wrangler.toml       تنظیمات / config
```

## راه‌اندازی / Setup (۴ مرحله)
1. `tools/hash.html` را در مرورگر باز کنید، رمز را بنویسید (۱۲+ کاراکتر) و خط خروجی را در `src/credentials.js` جلوی `PASSWORD_HASH` بگذارید. نام کاربری `Theo-Parsa` است.
2. پروژه را در گیت‌هاب push کنید.
3. Cloudflare → Workers & Pages → Create → **Import a repository** → همین ریپو → Deploy. (هر push بعدی خودکار دیپلوی می‌شود.)
   فضای ذخیره (KV با نام `DATA`) خودکار ساخته می‌شود؛ اگر خطای `id` داد: `npx wrangler kv namespace create DATA` و `id = "..."` را زیر `[[kv_namespaces]]` اضافه کنید.
4. `/admin` را باز کنید و وارد شوید.

Local test: `npm install && npm run dev` → http://localhost:8787/admin

## قابلیت‌های پنل / Admin
اعضا (۴ جایگاه ثابت، عکس پروفایل) · پروژه‌ها (افزودن/ویرایش/حذف، کاور، ویدیو، پیش‌نویس/انتشار) · رسانه (آپلود JPG/PNG/WebP تا ۸MB و MP4/WebM تا ۲۴MB) · داشبورد · دو زبان و دو تم.

## امنیت / Security
- رمز هرگز ذخیره نمی‌شود؛ فقط هش نمک‌دار PBKDF2-SHA256 (۱۰۰٬۰۰۰ تکرار، حداکثر مجاز Workers). فرمول در بالای `src/worker.js` است.
- ⚠️ اگر ریپو **عمومی** است، هش هم عمومی است و حدس‌زدن آفلاین ممکن است: رمز بلند و تصادفی (۱۶+ کاراکتر) بگذارید، یا ریپو را خصوصی کنید، یا هش را به‌جای فایل در Cloudflare به‌عنوان secret با نام `ADMIN_PASSWORD_HASH` بگذارید (بر فایل مقدم است).
- ورود: حداکثر ۵ تلاش ناموفق در ۱۵ دقیقه برای هر IP، پیام خطای یکسان، کوکی HttpOnly/Secure/SameSite=Strict (۸ ساعت)، توکن CSRF، CSP با nonce، `noindex`.
- آپلود: نوع فایل از بایت‌های اول تشخیص داده می‌شود (نه از نام)؛ SVG و فایل اجرایی رد می‌شود؛ فقط ادمین آپلود می‌کند.
- بازیابی/تغییر رمز: دوباره `tools/hash.html` → جایگزینی هش → push.

محدودیت: KV نهایتاً هم‌گام است (تغییرات عمومی تا ~۱ دقیقه دیرتر دیده می‌شود)، فایل‌ها حداکثر ۲۴MB؛ برای ویدیوی سنگین‌تر از YouTube/Stream استفاده کنید.
