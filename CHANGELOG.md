# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/),
verzování dle [Semantic Versioning](https://semver.org/lang/cs/)
(MAJOR.MINOR.PATCH).

Aktuální verze je vždy vidět v patičce běžící aplikace a v
[GitHub Releases](../../releases).

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
