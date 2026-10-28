# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/),
verzování dle [Semantic Versioning](https://semver.org/lang/cs/)
(MAJOR.MINOR.PATCH).

Aktuální verze je vždy vidět v patičce běžící aplikace a v
[GitHub Releases](../../releases).

## [1.1.0] — 2026-10-28

### Změněno (anonymita)

- Rate limit je nyní jediné globální počítadlo za hodinu, **bez IP adresy**
  (ani hashe). Dříve se ukládal per-IP `HMAC(IP)` soubor; ten umožňoval
  správci s přístupem k souborům a k e-mailu odvodit IP odesílatele
  a škodil uživatelům za společnou adresou (škola, Tor). Staré soubory
  `storage/ratelimit/*.json` je možné smazat.
- E-mail neobsahuje přesný čas (hlavička `Date` zaokrouhlena na hodinu), jméno
  serveru v `Message-ID`/HELO ani `X-Mailer` s verzí PHPMailer.
- Texty na stránce i v README přesněji popisují, co aplikace dělá (a že
  přístupové logy webserveru ovlivnit nemůže).

### Opraveno

- Captcha token je jednorázový (nonce + zneplatnění po použití).
- Pole formuláře musí být řetězce a platné UTF-8.
- Po úspěšném odeslání přesměrování (303) — obnovení stránky už neodešle
  hlášení znovu.
- Selhání odeslání e-mailu se zapíše do PHP error logu (bez IP a obsahu).
- `.user.ini` omezuje velikost požadavku (64 kB) a vypíná uploady.
- Konfiguraci lze přesunout mimo DocumentRoot (`WB_CONFIG`, `storage_dir`).
- Konfigurace rozdělena na veřejnou (`config.public.php` — adresát, odesílatel,
  SMTP server; v gitu) a tajnou (`config.local.php` — klíč a heslo; mimo git).
  Tajná vrstva nesmí přepsat veřejné hodnoty. Stránka ukazuje, kam se hlášení
  odesílají, s odkazem na veřejný soubor.

## [1.0.0] — 2026-08-18

První verze.

### Přidáno

- Anonymní formulář pro hlášení (text zprávy + volitelné jméno, telefon,
  e-mail), odeslání přes PHPMailer/SMTP na pevně nastavenou adresu.
- Anti-spam bez cizích služeb: honeypot, bezstavová HMAC captcha s časovou
  pojistkou, jemný rate limit dle soleného hashe IP adresy.
- Bezpečnostní hlavičky (CSP, Permissions-Policy, no-store cache,
  COOP/CORP, HSTS) a `.htaccess` pro nasazení na Apache.
- Self-hostované písmo Raleway (žádné požadavky na třetí strany).
- Vzhled dle design systému školy (glassmorphism, značkové barvy).
- Rozbalovací panel s podrobným vysvětlením anonymity a bezpečnosti pro
  návštěvníky formuláře.
- Podrobná dokumentace v README.md (laicky i technicky).
