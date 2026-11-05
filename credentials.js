// Admin credentials (separate file). The password is NEVER stored — only its salted PBKDF2 hash.
// 1) Open tools/hash.html in your browser (works offline), type your password, copy the result.
// 2) Paste it between the quotes below.  (A Cloudflare secret named ADMIN_PASSWORD_HASH overrides this.)
export const USERNAME = "Theo-Parsa";
export const PASSWORD_HASH = "pbkdf2$100000$aBCz1lT627ZJmZKqszfK5g==$0j2pFNa3nR+crOyEm6R+DySB9edaC+RwEmVmnQQACVY="; // pbkdf2$100000$<salt>$<hash>
