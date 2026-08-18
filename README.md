# Whistleblowing — anonymní oznamovací formulář

[![GitHub release](https://img.shields.io/github/v/release/skolavdf-dev/whistleblowing?label=verze&sort=semver)](https://github.com/skolavdf-dev/whistleblowing/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

Otevřený, jednoduchý a auditovatelný formulář pro anonymní nahlašování
podezření na protiprávní nebo neetické jednání ve škole **VOŠ, SPŠ a SOŠ
Varnsdorf**. Vyplněná zpráva se e-mailem odešle na předem nastavenou
adresu. Žádná databáze, žádné uživatelské účty, žádné sledování.

Zdrojový kód je veřejný záměrně — smyslem je, aby si kdokoliv (nejen
programátor) mohl ověřit, že aplikace se zprávou nakládá přesně tak, jak
tvrdí, a nic víc. Odkaz na tento repozitář je proto přímo na stránce
formuláře.

---

## 1. Co aplikace dělá (pro každého)

1. Otevřete stránku formuláře.
2. Napíšete, co se stalo. Jméno, telefon a e-mail jsou **čistě dobrovolné**
   — vyplňte je jen tehdy, pokud chcete být kontaktováni kvůli dalšímu
   šetření.
3. Po odeslání zpráva odejde e-mailem na adresu vedení/pověřené osoby
   (aktuálně nastaveno na `whistleblowing@skolavdf.cz`, viz konfigurace).
4. Aplikace si nic nepamatuje. Jakmile je e-mail odeslán, na serveru
   nezůstává žádná stopa po tom, kdo a co napsal.

Formulář **nepoužívá cookies, nepřihlašuje vás, nesleduje vás** a
nenačítá nic z cizích webů (žádné reklamní/analytické skripty, žádné
fonty z Google apod.) — viz kapitola [Anonymita](#3-anonymita---co-aplikace-záměrně-nedělá).

### Co formulář neumí (záměrně)

- **Přílohy souborů.** Nahrávání souborů je běžný vektor útoku (škodlivý
  obsah, metadata prozrazující autora fotky, apod.) a pro jednoduchý
  textový formulář není nutné. Lze doplnit později, pokud bude potřeba.
- **Sledování stavu hlášení.** Bez databáze a bez identifikace odesílatele
  nelze nabídnout „přihlaste se a sledujte vyřízení". To je vědomý
  kompromis ve prospěch anonymity a jednoduchosti.

---

## 2. Jak to funguje pod kapotou (přehled pro techniky)

Aplikace je úmyslně **jeden PHP soubor** ([index.php](index.php)) plus pár
pomocných funkcí — žádný framework, žádné MVC, žádné OOP vrstvy navíc.
Cíl: aby šel celý tok požadavku přečíst od začátku do konce bez skákání
mezi desítkami souborů.

```
Návštěvník → GET  index.php   → vykreslí prázdný formulář + nový anti-spam token
Návštěvník → POST index.php   → validace → PHPMailer → SMTP → e-mail doručen
                                → aplikace zapomene, že k tomu došlo
```

Klíčové soubory:

| Soubor | Účel |
|---|---|
| [index.php](index.php) | Celá aplikační logika + HTML formulář |
| [config.php](config.php) | Výchozí konfigurace, definuje konstanty |
| `config.local.php` | Lokální tajné hodnoty (SMTP heslo, HMAC klíč) — **není v gitu** |
| [includes/helpers.php](includes/helpers.php) | `e()`, anti-spam captcha, rate limit, čištění vstupu |
| [templates/mail.html](templates/mail.html) | HTML šablona odesílaného e-mailu |
| [assets/css/style.css](assets/css/style.css) | Vzhled dle design systému školy |
| [assets/fonts/](assets/fonts/) | Self-hostované písmo Raleway |
| [storage/ratelimit/](storage/) | Dočasné soubory rate limiteru (auto-expirují) |
| [.htaccess](.htaccess) | Apache: HTTPS redirect, blokace `vendor/`, config souborů a dotfiles, hlavičky pro statické soubory |
| [includes/.htaccess](includes/.htaccess), [templates/.htaccess](templates/.htaccess), [storage/.htaccess](storage/.htaccess), [.claude/.htaccess](.claude/.htaccess) | Úplná blokace webového přístupu k danému adresáři |

Závislosti: jediná — [PHPMailer](https://github.com/PHPMailer/PHPMailer)
přes Composer, pro odesílání e-mailu přes autentizované SMTP.

---

## 3. Anonymita — co aplikace záměrně nedělá

Toto je jádro důvěryhodnosti celého nástroje, proto je rozepsané podrobně.

### Laicky

- Nevíme, kdo formulář vyplnil, pokud nám to sám neřekne (jméno/telefon/
  e-mail jsou dobrovolné).
- Neukládáme si žádné technické stopy — žádné cookies, žádné přihlašování,
  žádné „otisky prohlížeče".
- Stránka nenačítá nic od třetích stran (Google, reklamní sítě, sledovací
  skripty) — i tohle by mohlo prozradit, že jste stránku navštívili.
- Odkaz na GitHub v patičce vede na tento samý kód — můžete si ověřit, že
  neděláme nic jiného, než co je tady popsáno.

### Technicky

- **Žádná session, žádné cookies.** Aplikace nikde nevolá `session_start()`
  ani `setcookie()`. Bez session nelze požadavky napříč návštěvami mezi
  sebou provázat.
- **Anti-spam captcha je bezstavová.** Místo uložení očekávané odpovědi do
  session je celá „úloha" (dvě čísla + čas + HMAC podpis) zakódovaná přímo
  ve skrytých polích formuláře (`captcha_generate()` /
  `captcha_verify()` v [includes/helpers.php](includes/helpers.php)).
  Podpis (`hash_hmac('sha256', …, APP_SECRET)`) zaručuje, že hodnoty nejde
  zfalšovat bez znalosti tajného klíče ze serveru, a přitom nevyžaduje
  žádné úložiště na straně serveru.
- **IP adresa se nikde neloguje.** Jediné místo, kde s ní aplikace vůbec
  pracuje, je jemný rate limiter (`check_rate_limit()`). I tam se IP nikdy
  neukládá v čitelné podobě — použije se `substr(hash_hmac('sha256', $ip,
  APP_SECRET), 0, 24)` jako název dočasného souboru, jehož obsah je jen
  `{"start": …, "count": …}`. Z tohoto hashe nejde IP adresu zpětně
  odvodit (je solený tajným klíčem) a soubor navíc sám vyprší
  (`RATE_LIMIT_WINDOW`, výchozí 1 hodina). Nikde se neváže na obsah
  konkrétní zprávy.
- **Žádné požadavky na třetí strany.** Písmo Raleway je stažené a uložené
  lokálně v [assets/fonts/](assets/fonts/) místo načítání z
  `fonts.googleapis.com` / `fonts.gstatic.com` — jinak by prohlížeč
  každého návštěvníka poslal Googlu svou IP adresu jen tím, že si stránku
  otevře. Ze stejného důvodu formulář nepoužívá žádnou externí anti-spam
  službu (reCAPTCHA apod.).
- **`Referrer-Policy: no-referrer`** — při kliknutí na odkaz na GitHub se
  cílové stránce nepředává, že návštěvník přišel z whistleblowingového
  formuláře.
- **`Cache-Control: no-store, no-cache, must-revalidate`** — na sdíleném/
  školním počítači se stránka (včetně rozepsaného textu hlášení, který se
  při chybě validace vrací zpět do pole) neuloží do disk cache ani do
  zpět/vpřed historie prohlížeče. Bez toho by po odchodu od počítače mohl
  další člověk tlačítkem „Zpět" uvidět částečně napsané hlášení.
- **`Permissions-Policy`** explicitně zakazuje kameru, mikrofon,
  geolokaci a platby — stránka o ně nikdy nežádá, ale hlavička to
  deklaruje i pro případné vložené/kompromitované skripty. Obsahuje i
  opt-out z Google Topics/FLoC (`browsing-topics=()`, `interest-cohort=()`).
- **Žádný JavaScript.** Celý formulář funguje na čistém HTML/CSS/PHP —
  menší plocha pro útok, funguje i s vypnutým JS, a nic se neposílá
  „potichu" přes fetch/XHR mimo samotné odeslání formuláře.

---

## 4. Bezpečnost — detailní přehled

### 4.1 HTTP hlavičky

Nastavují se na začátku [index.php](index.php) pro každou odpověď:

| Hlavička | Hodnota | Proti čemu chrání |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; form-action 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests` | XSS (žádný inline/externí JS není povolen), exfiltrace dat přes formulář na cizí doménu, clickjacking, vkládání pluginů |
| `X-Content-Type-Options` | `nosniff` | MIME-sniffing útoky |
| `X-Frame-Options` | `DENY` | Clickjacking (vložení stránky do cizího `<iframe>`) |
| `Referrer-Policy` | `no-referrer` | Únik URL/kontextu při odchodu ze stránky |
| `Cross-Origin-Opener-Policy` | `same-origin` | Izolace okna od cizích originů (obrana proti Spectre-style útokům) |
| `Cross-Origin-Resource-Policy` | `same-origin` | Cizí web nemůže vložit/číst zdroje z této stránky |
| `Permissions-Policy` | kamera/mikrofon/geolokace/platby `=()` | Zakázání nepotřebných prohlížečových API |
| `Cache-Control` / `Pragma` | `no-store, no-cache, must-revalidate` / `no-cache` | Ponechání citlivého obsahu (rozepsané hlášení) v cache sdíleného počítače |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (jen když běží přes HTTPS) | Vynucení HTTPS při produkčním nasazení |

Navíc: `header_remove('X-Powered-By')` skrývá verzi PHP a
`ini_set('display_errors', '0')` zajišťuje, že se chybové výpisy PHP
nikdy nezobrazí návštěvníkovi, i kdyby to hosting měl špatně nastavené.

Statické soubory (CSS, fonty) tyto hlavičky od `index.php` **nedostávají**
— obsluhuje je přímo webserver, ne PHP. Proto [.htaccess](.htaccess) přes
`mod_headers` posílá i pro ně alespoň základní trojici
(`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`); zbytek
(CSP, Permissions-Policy, no-store…) dává smysl jen pro samotnou stránku
formuláře, takže zůstává jen v `index.php`.

### 4.2 Ochrana na úrovni webserveru ([.htaccess](.htaccess))

Pro nasazení na Apache (typicky sdílený hosting jako Forpsi) doplňuje
aplikační hlavičky:

- **Vynucení HTTPS** — přesměruje `http://` na `https://`, jinak by
  `Strict-Transport-Security` z `index.php` nikdy neměl šanci se
  prohlížeči dostat (posílá se jen když spojení už je zabezpečené).
- **Blokace přímého stažení konfigurace** — `config.php`,
  `config.local.php`, `composer.json/lock` vrátí `403`, i kdyby byl PHP
  na serveru někdy nesprávně nastavený a servíroval `.php` soubory jako
  čistý text místo jejich spuštění. `config.local.php` obsahuje SMTP
  heslo a `APP_SECRET` — toto je poslední záchranná brzda, kdyby selhalo
  vše ostatní.
- **Blokace tečkových souborů** (`.git`, `.env`, `.htaccess` samotné…) —
  `<FilesMatch "^\.">`.
- **Úplná blokace adresářů**, které nemají být dostupné přes web —
  vlastní `.htaccess` v [includes/](includes/.htaccess),
  [templates/](templates/.htaccess), [storage/](storage/.htaccess) a
  [.claude/](.claude/.htaccess) (dev nástroje). `vendor/` (generovaný
  composerem, není v gitu, takže nemůže mít vlastní `.htaccess`, jinak by
  se ztrácel při každém `composer install`) blokuje centrálně pravidlo
  `RewriteRule ^vendor/ - [F,L]` v kořenovém souboru.
- **`Options -Indexes`** — vypnutý výpis obsahu adresáře, pokud by v něm
  náhodou chyběl `index.php`/`index.html`.

Ověřeno lokálně proti reálnému Apache 2.4 (viz commit historie) — všechny
citlivé cesty vrací `403`, veřejné soubory (`assets/`, `index.php`)
zůstávají dostupné `200`.

> **Nasazení na hosting bez `mod_rewrite`/`mod_headers`/`AllowOverride`:**
> Sdílené hostingy (Forpsi apod.) je mají obvykle povolené výchozí, ale
> pokud `.htaccess` na produkci „nezabírá", ověřte u poskytovatele, že má
> `AllowOverride All` a zmíněné moduly aktivní.

### 4.3 Ochrana proti spamu a botům (bez cizích služeb)

Tři nezávislé mechanismy, žádný z nich nevyžaduje session ani externí
službu typu reCAPTCHA:

1. **Honeypot** — skryté pole `company` (CSS `position: absolute; left:
   -9999px`, `aria-hidden="true"`, `tabindex="-1"`). Člověk ho nikdy
   nevidí ani se do něj neprotabuluje, ale jednoduší boti ho běžně
   vyplní. Pokud přijde vyplněné, aplikace předstírá úspěch (`$sent =
   true`), ale **e-mail se fakticky neodešle** — bot tak nezjistí, že byl
   odhalen, a nezkouší to jinak.
2. **Stateless HMAC captcha** — viz kapitola Anonymita výše. Kromě
   ověření správné odpovědi kontroluje i stáří tokenu
   (`CAPTCHA_MIN_SECONDS` = 3 s, `CAPTCHA_MAX_SECONDS` = 3600 s) — příliš
   rychlé odeslání prozradí automat, příliš staré odmítne jako replay.
3. **Rate limit** dle soleného hashe IP adresy — výchozí limit 5 hlášení
   za hodinu (`RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` v
   [config.php](config.php)). Implementace je „fail-open": pokud dočasné
   úložiště selže (např. špatná oprávnění na hostingu), radši propustí
   požadavek, než aby zablokovala skutečného oznamovatele. Lze úplně
   vypnout (`rate_limit_enabled => false` v `config.local.php`).

### 4.4 Ochrana proti injection útokům

- **XSS:** veškerý výstup do HTML prochází přes `e()`
  (`htmlspecialchars(…, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`) — jak na
  stránce formuláře, tak v textu e-mailu (`nl2br(e($plainBody))`).
- **E-mail header / SMTP injection:** zpráva se skládá výhradně přes
  parametrizované PHPMailer API — `setFrom()`, `addAddress()`,
  `addReplyTo()`. Hlavičky se nikde neskládají ručně řetězením s
  uživatelským vstupem, takže vložení `\r\n` do libovolného pole nemůže
  přidat vlastní SMTP příkaz ani hlavičku. Jako obranu do hloubky navíc
  `clean_line()` / `clean_message()` v
  [includes/helpers.php](includes/helpers.php) odstraňují řídicí znaky
  (`\x00`–`\x1F`, `\x7F`) ze všech vstupů ještě před předáním PHPMaileru.
- **Předmět e-mailu je pevný** (`REPORT_SUBJECT = 'Whistleblowing'`,
  konstanta v [config.php](config.php)) — návštěvník do něj nemá žádný
  vstup, takže ho nejde zneužít k manipulaci s hlavičkou `Subject`.
- **Příjemce e-mailu je pevný** (`REPORT_TO_EMAIL` z konfigurace) —
  formulář nemá pole pro zadání příjemce, takže ho nelze zneužít jako
  otevřený mail relay.
- **Volitelný e-mail odesílatele** se validuje přes
  `filter_var($email, FILTER_VALIDATE_EMAIL)` a používá se pouze jako
  `Reply-To`, nikdy jako `From` (ten zůstává pevně nastavený systémový
  účet) — díky tomu nejde podvrhnout identitu odesílatele v hlavičce
  `From`.
- **Telefon** prochází whitelistem povolených znaků
  (`/^[0-9+\-\s()]+$/u`), **jméno** a **zpráva** mají limity délky
  (`MAX_NAME_LENGTH`, `MAX_MESSAGE_LENGTH`) kontrolované přes
  `mb_strlen()` — při překročení se vrátí čitelná chyba, vstup se
  **neořezává potichu** (aby whistleblower nepřišel o část hlášení, aniž
  by to poznal).
- **SQL injection:** není relevantní — aplikace nemá žádnou databázi.

### 4.5 Chybové stavy

Výjimka z PHPMaileru (`PHPMailerException`) se zachytává a návštěvníkovi
se ukáže jen obecná zpráva „Odeslání se bohužel nezdařilo." — detaily
SMTP chyby (které by mohly prozradit interní infrastrukturu) se
nezobrazují. Zvažte logování těchto výjimek na serverové straně (do
běžného PHP error logu, bez obsahu zprávy) pro monitoring dostupnosti
SMTP.

---

## 5. Instalace

Požadavky: PHP ≥ 8.1, [Composer](https://getcomposer.org/).

```bash
composer install
cp config.local.example.php config.local.php
```

V `config.local.php` doplňte:

| Klíč | Popis |
|---|---|
| `app_secret` | Náhodný tajný řetězec pro podpis anti-spam tokenů a rate-limit hashů. Vygenerujte např. `php -r "echo bin2hex(random_bytes(32));"` |
| `report_to` | E-mail, na který se mají hlášení posílat |
| `github_url` | Odkaz na tento repozitář (zobrazuje se na stránce kvůli transparentnosti) |
| `smtp_host`, `smtp_port`, `smtp_user`, `smtp_pass`, `smtp_from`, `smtp_from_name`, `smtp_secure` | Přístup k SMTP serveru |
| `rate_limit_enabled`, `rate_limit_max`, `rate_limit_window` | Volitelné přepsání výchozích limitů z [config.php](config.php) |

`config.local.php` obsahuje citlivé údaje a je v `.gitignore` — **nikdy
ho necommitujte**.

### Lokální spuštění

```bash
php -S localhost:8090
```

a otevřete `http://localhost:8090`.

> PHP vestavěný server (`php -S`) **nečte `.htaccess`** — ochrany popsané
> v kapitole [4.2](#42-ochrana-na-úrovni-webserveru-htaccess) se lokálně
> tímto způsobem neprojeví, fungují jen pod skutečným Apache.

### Nasazení na produkci

- Nahrajte celý adresář (včetně `vendor/`, vygenerovaného přes
  `composer install --no-dev`, a všech `.htaccess` souborů) na webhosting
  s Apache a PHP ≥ 8.1.
- Hosting musí mít `AllowOverride All` (nebo alespoň
  `AllowOverride AuthConfig Limit Indexes`) a moduly `mod_rewrite` +
  `mod_headers` aktivní — jinak `.htaccess` nebude fungovat. Na běžném
  sdíleném hostingu (Forpsi apod.) to bývá výchozí.
- **Pouze přes HTTPS** — bez něj se nezapne `Strict-Transport-Security` a
  formulářová data (byť anonymní) by putovala nešifrovaně.
  `.htaccess` na HTTPS automaticky přesměruje; pokud doména ještě nemá
  certifikát, dočasně zakomentujte blok „Vynucení HTTPS" v
  [.htaccess](.htaccess), jinak by byla stránka nedostupná.
- Adresář `storage/` musí být zapisovatelný pro webserver (slouží jen pro
  dočasné soubory rate limiteru, ne pro obsah zpráv).
- Ověřte, že doména má nastavené SPF/DKIM/DMARC pro odchozí SMTP doménu —
  jinak mohou zprávy končit ve spamu příjemce.
- Před commitem/publikací zkontrolujte, že `config.local.php` skutečně
  není v gitu (`git status` by ho neměl vidět).

---

## 6. Čemu aplikace nezabrání (hranice řešení)

Pro upřímnost k uživatelům formuláře i k budoucím auditorům kódu:

- **Síťová úroveň zůstává mimo kontrolu aplikace.** Provozovatel serveru
  (hosting) může technicky vidět přístupové/webserverové logy na úrovni
  webserveru (Apache/Nginx) nebo síťové infrastruktury — to už aplikace
  neřídí. Doporučujeme provozovateli tyto logy pro cestu k formuláři
  minimalizovat/anonymizovat, pokud to daný hosting umožňuje.
  Whistleblower, který chce nejvyšší možnou anonymitu, by měl zvážit
  přístup přes síť, která jeho IP adresu neprozradí (např. z veřejné
  sítě mimo školu).
- **Obsah samotné zprávy** může nechtěně prozradit identitu (styl psaní,
  konkrétní detaily, které zná málokdo). To žádná technická ochrana
  nevyřeší — je na autorovi hlášení, co považuje za bezpečné napsat.
- **Rate limit dle IP** je kompromis: bez jakéhokoliv omezení by šel
  formulář snadno zahltit; s omezením dle IP existuje teoretická situace,
  kdy více lidí za NAT (např. školní síť) sdílí limit. Proto je nastavený
  velkoryse a lze ho v konfiguraci vypnout.

---

## 7. Verzování

Aplikace má jednoduché ruční verzování dle
[Semantic Versioning](https://semver.org/lang/cs/) (`MAJOR.MINOR.PATCH`):

- **Aktuální verze běžícího webu** se zobrazuje v patičce každé stránky
  (konstanta `APP_VERSION` v [config.php](config.php)) — návštěvník tak
  vždy vidí, jakou verzi zrovna používá.
- **Historie změn** je v [CHANGELOG.md](CHANGELOG.md).
- **Na GitHubu** je aktuální verze vidět v sekci
  [Releases](../../releases) a v odznaku (badge) nahoře v tomto README,
  který se automaticky aktualizuje podle poslední vydané release.

### Jak vydat novou verzi

1. Zvyšte `APP_VERSION` v [config.php](config.php).
2. Přidejte záznam do [CHANGELOG.md](CHANGELOG.md) s tím, co se změnilo.
3. Commitněte a otagujte:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```
4. Na GitHubu z tagu vytvořte Release (GitHub → *Releases* → *Draft a new
   release*) — badge v README i sekce Releases se pak automaticky ukážou
   jako aktuální.
