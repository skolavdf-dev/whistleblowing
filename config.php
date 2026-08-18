<?php
declare(strict_types=1);

/**
 * config.php — centrální konfigurace aplikace
 *
 * Citlivé a instalačně specifické hodnoty (SMTP heslo, tajný klíč, cílový
 * e-mail) se nastavují v config.local.php, který se necommituje do gitu.
 * Zde jsou jen výchozí hodnoty a věci, které je v pořádku mít veřejně
 * v repozitáři (projekt je open source kvůli transparentnosti).
 */

$_localCfg = [];
if (file_exists(__DIR__ . '/config.local.php')) {
    $_localCfg = require __DIR__ . '/config.local.php';
}

if (($_localCfg['app_secret'] ?? '') === '') {
    http_response_code(500);
    exit('Aplikace není nakonfigurována (chybí app_secret). Zkopírujte config.local.example.php jako config.local.php a doplňte hodnoty.');
}

// ─── Verze aplikace ─────────────────────────────────────────────────────────
// Zobrazuje se v patičce webu. Zvyšujte ručně dle SemVer (MAJOR.MINOR.PATCH)
// při každé změně, kterou stojí za to označit — souběžně s novým záznamem
// v CHANGELOG.md a git tagem (např. "v1.1.0") při vydání na GitHubu.
define('APP_VERSION', '1.0.0');

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
define('SMTP_USER', $_localCfg['smtp_user'] ?? '');
define('SMTP_PASS', $_localCfg['smtp_pass'] ?? '');
define('SMTP_FROM', $_localCfg['smtp_from'] ?? '');
define('SMTP_FROM_NAME', $_localCfg['smtp_from_name'] ?? 'Whistleblowing');
define('SMTP_SECURE', $_localCfg['smtp_secure'] ?? 'tls');

// ─── Limity a anti-spam ─────────────────────────────────────────────────────
// Minimální / maximální stáří anti-spam tokenu (ochrana proti botům a replay útoku).
define('CAPTCHA_MIN_SECONDS', 3);       // formulář vyplněný rychleji je podezřelý
define('CAPTCHA_MAX_SECONDS', 3600);    // token starší než hodinu už neplatí

// Maximální délky vstupů.
define('MAX_MESSAGE_LENGTH', 8000);
define('MAX_NAME_LENGTH', 200);
define('MAX_PHONE_LENGTH', 40);

// Jemný rate limit dle nevratného hashe IP adresy — pouze krátkodobá ochrana
// proti hromadnému zahlcení, nikdy se neukládá spolu s obsahem zprávy ani
// jinde v aplikaci. Lze zcela vypnout nastavením 'rate_limit_enabled' => false.
define('RATE_LIMIT_ENABLED', $_localCfg['rate_limit_enabled'] ?? true);
define('RATE_LIMIT_MAX', $_localCfg['rate_limit_max'] ?? 5);
define('RATE_LIMIT_WINDOW', $_localCfg['rate_limit_window'] ?? 3600);
define('STORAGE_DIR', __DIR__ . '/storage');

unset($_localCfg);
