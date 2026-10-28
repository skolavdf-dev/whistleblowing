<?php
declare(strict_types=1);

/**
 * config.php — centrální konfigurace aplikace
 *
 * Konfigurace má dvě vrstvy:
 *   - config.public.php (v gitu): vše, co smí a má být veřejné — kam hlášení
 *     jdou (adresát), odkud se posílají (odesílatel, SMTP server). Kdokoli si
 *     v repozitáři ověří, že hlášení nejdou nikam jinam.
 *   - config.local.php (mimo git): jen tajné hodnoty (app_secret, SMTP heslo,
 *     případně SMTP uživatel) a provozní ladění (storage_dir, rate_limit_*).
 *     Nesmí přepisovat veřejné hodnoty — jinak by veřejný soubor nemusel
 *     odpovídat skutečnosti, a aplikace se v takovém případě odmítne spustit.
 */

// Cestu ke konfiguraci lze přesunout mimo DocumentRoot proměnnou prostředí WB_CONFIG
// (soubor pak není ve webrootu vůbec).
$_localCfgPath = getenv('WB_CONFIG') ?: __DIR__ . '/config.local.php';
$_publicCfg = require __DIR__ . '/config.public.php';
$_localCfg = [];
if (is_file($_localCfgPath)) {
    $_localCfg = require $_localCfgPath;
}

$_overridden = array_intersect_key($_localCfg, $_publicCfg);
if ($_overridden !== []) {
    http_response_code(500);
    exit('Chyba konfigurace: config.local.php nesmí obsahovat veřejné hodnoty (' . implode(', ', array_keys($_overridden)) . '). Patří do config.public.php.');
}
$_localCfg += $_publicCfg;

if (($_localCfg['app_secret'] ?? '') === '') {
    http_response_code(500);
    exit('Aplikace není nakonfigurována (chybí app_secret). Zkopírujte config.local.example.php jako config.local.php a doplňte hodnoty.');
}

// ─── Verze aplikace ─────────────────────────────────────────────────────────
// Zobrazuje se v patičce webu. Zvyšujte ručně dle SemVer (MAJOR.MINOR.PATCH)
// při každé změně, kterou stojí za to označit — souběžně s novým záznamem
// v CHANGELOG.md a git tagem (např. "v1.1.0") při vydání na GitHubu.
define('APP_VERSION', '1.1.0');

// ─── Cíl hlášení ────────────────────────────────────────────────────────────
define('REPORT_TO_EMAIL', $_localCfg['report_to'] ?? 'whistleblowing@skolavdf.cz');
define('REPORT_SUBJECT', 'Whistleblowing');

// ─── Transparentnost ────────────────────────────────────────────────────────
define('GITHUB_REPO_URL', $_localCfg['github_url'] ?? '');

// ─── Tajný klíč pro HMAC (podpis anti-spam tokenů) ─────────────────────────
define('APP_SECRET', $_localCfg['app_secret']);

// ─── SMTP ───────────────────────────────────────────────────────────────────
define('SMTP_HOST', $_localCfg['smtp_host'] ?? '');
define('SMTP_PORT', $_localCfg['smtp_port'] ?? 587);
define('SMTP_USER', $_localCfg['smtp_user'] ?? $_localCfg['smtp_from'] ?? '');   // výchozí: stejné jako odesílatel
define('SMTP_PASS', $_localCfg['smtp_pass'] ?? '');
define('SMTP_FROM', $_localCfg['smtp_from'] ?? '');
define('SMTP_FROM_NAME', $_localCfg['smtp_from_name'] ?? 'Whistleblowing');
define('SMTP_SECURE', $_localCfg['smtp_secure'] ?? 'tls');
// Doména v Message-ID a HELO (místo jména serveru); výchozí je doména odesílatele.
define('MAIL_DOMAIN', $_localCfg['mail_domain'] ?? (str_contains((string) ($_localCfg['smtp_from'] ?? ''), '@')
    ? substr((string) strrchr((string) $_localCfg['smtp_from'], '@'), 1) : 'localhost'));

// ─── Limity a anti-spam ─────────────────────────────────────────────────────
// Minimální / maximální stáří anti-spam tokenu (ochrana proti botům a replay útoku).
define('CAPTCHA_MIN_SECONDS', 3);       // formulář vyplněný rychleji je podezřelý
define('CAPTCHA_MAX_SECONDS', 3600);    // token starší než hodinu už neplatí

// Maximální délky vstupů.
define('MAX_MESSAGE_LENGTH', 8000);
define('MAX_NAME_LENGTH', 200);
define('MAX_PHONE_LENGTH', 40);

// Globální rate limit — jediné počítadlo pro celý web, BEZ jakékoli vazby na IP
// adresu. Chrání jen před zahlcením formuláře; nikdy neobsahuje nic, podle čeho
// by šlo odlišit odesílatele (ani hash IP). Čas se ukládá jen jako začátek hodiny.
// Lze vypnout nastavením 'rate_limit_enabled' => false.
define('RATE_LIMIT_ENABLED', $_localCfg['rate_limit_enabled'] ?? true);
define('RATE_LIMIT_MAX', $_localCfg['rate_limit_max'] ?? 30);   // hlášení za hodinu celkem
define('STORAGE_DIR', $_localCfg['storage_dir'] ?? __DIR__ . '/storage');

unset($_localCfg, $_localCfgPath, $_publicCfg, $_overridden);
