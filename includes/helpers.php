<?php
declare(strict_types=1);

/**
 * helpers.php — pomocné funkce
 *
 * Aplikace je záměrně bezstavová: nepoužívá PHP session ani cookies,
 * aby nezanechávala žádné stopy v prohlížeči návštěvníka a aby jednotlivé
 * requesty nešlo mezi sebou nijak korelovat. Anti-spam ochrana (captcha,
 * časová pojistka) je proto implementována jako podepsaný token přímo
 * ve formuláři (stateless, HMAC), nikoliv přes session.
 *
 * S IP adresou návštěvníka aplikace nepracuje vůbec: neloguje se, neukládá
 * ani nehashuje. Rate limit je jediné globální počítadlo za hodinu
 * (viz check_rate_limit níže).
 */

/** Bezpečný výstup do HTML — ochrana proti XSS. */
function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Odstraní řídicí znaky a zalomení řádků z jednořádkového vstupu.
 * Obrana do hloubky proti header injection (CRLF), i když PHPMailer
 * hlavičky sám validuje a escapuje.
 */
function clean_line(string $s): string
{
    $s = trim($s);
    return preg_replace('/[\x00-\x1F\x7F]/', '', $s) ?? '';
}

/** Vyčistí víceřádkový text zprávy — ponechá odřádkování, odstraní ostatní řídicí znaky. */
function clean_message(string $s): string
{
    $s = trim($s);
    $s = preg_replace('/\r\n|\r/', "\n", $s) ?? $s;
    return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s) ?? '';
}

/** Vrátí POST pole jako řetězec; pole (message[]=…) a chybějící hodnoty dávají null. */
function post_string(string $key): ?string
{
    $v = $_POST[$key] ?? null;
    return is_string($v) ? $v : null;
}

/** Je řetězec platné UTF-8? (neplatné bajty by mohly poškodit e-mail) */
function is_utf8(string $s): bool
{
    return mb_check_encoding($s, 'UTF-8');
}

/**
 * Vygeneruje stateless anti-spam token (jednoduchá matematická úloha).
 * Podepsáno HMAC pomocí APP_SECRET — nelze podvrhnout ani přečíst
 * odpověď bez znalosti tajného klíče. Součástí podpisu je náhodný nonce,
 * takže každý token je jedinečný a po použití ho lze zneplatnit
 * (viz captcha_consume).
 *
 * @return array{num1:int, num2:int, ts:int, nonce:string, sig:string}
 */
function captcha_generate(): array
{
    $num1  = random_int(1, 9);
    $num2  = random_int(1, 9);
    $ts    = time();
    $nonce = bin2hex(random_bytes(8));
    $sig   = hash_hmac('sha256', "{$num1}:{$num2}:{$ts}:{$nonce}", APP_SECRET);

    return ['num1' => $num1, 'num2' => $num2, 'ts' => $ts, 'nonce' => $nonce, 'sig' => $sig];
}

/**
 * Ověří anti-spam token a odpověď návštěvníka.
 * Kontroluje: platnost podpisu, stáří tokenu, jednorázovost (token nelze
 * odeslat dvakrát) a správnost výsledku. Token se spotřebuje i při špatné
 * odpovědi — formulář se po chybě vykreslí s novým tokenem.
 */
function captcha_verify(int $num1, int $num2, int $ts, string $nonce, string $sig, string $answer): bool
{
    if (!preg_match('/^[0-9a-f]{16}$/', $nonce)) {
        return false;
    }
    $expectedSig = hash_hmac('sha256', "{$num1}:{$num2}:{$ts}:{$nonce}", APP_SECRET);
    if (!hash_equals($expectedSig, $sig)) {
        return false;
    }

    $age = time() - $ts;
    if ($age < CAPTCHA_MIN_SECONDS || $age > CAPTCHA_MAX_SECONDS) {
        return false;
    }

    if (!captcha_consume($sig)) {
        return false;
    }

    $answer = trim($answer);
    if ($answer === '' || !ctype_digit($answer)) {
        return false;
    }

    return (int) $answer === $num1 + $num2;
}

/**
 * Zneplatní použitý token. Ukládá se jen zkrácený hash podpisu a čas vypršení
 * zaokrouhlený na celou hodinu — žádná IP, žádný obsah, žádná přesná doba
 * odeslání. Při chybě úložiště se chová "fail-open" (radši propustit než
 * zablokovat oznamovatele); zneužití dál brzdí globální rate limit.
 */
function captcha_consume(string $sig): bool
{
    if (!is_dir(STORAGE_DIR) && !@mkdir(STORAGE_DIR, 0700, true) && !is_dir(STORAGE_DIR)) {
        return true;
    }
    $fp = @fopen(STORAGE_DIR . '/captcha-used.json', 'c+');
    if ($fp === false) {
        return true;
    }

    try {
        flock($fp, LOCK_EX);
        $data = json_decode(stream_get_contents($fp) ?: '', true);
        $data = is_array($data) ? $data : [];
        $now  = time();
        $key  = substr(hash('sha256', $sig), 0, 32);

        // vyhodit prošlé záznamy (token je stejně neplatný po CAPTCHA_MAX_SECONDS)
        $data = array_filter($data, static fn($exp) => is_int($exp) && $exp > $now);
        if (isset($data[$key])) {
            return false;
        }
        $data[$key] = (int) (ceil(($now + CAPTCHA_MAX_SECONDS) / 3600) * 3600);

        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, json_encode($data));
        fflush($fp);

        return true;
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/**
 * Globální rate limit proti zahlcení formuláře (viz config.php).
 *
 * Jediné počítadlo pro celý web — aplikace s IP adresou návštěvníka vůbec
 * nepracuje, takže nemá co uložit ani prozradit. Uložen je jen začátek
 * aktuální hodiny a počet hlášení. Při problému s úložištěm "fail-open".
 */
function check_rate_limit(): bool
{
    if (!RATE_LIMIT_ENABLED) {
        return true;
    }
    if (!is_dir(STORAGE_DIR) && !@mkdir(STORAGE_DIR, 0700, true) && !is_dir(STORAGE_DIR)) {
        return true;
    }
    $fp = @fopen(STORAGE_DIR . '/ratelimit.json', 'c+');
    if ($fp === false) {
        return true;
    }

    try {
        flock($fp, LOCK_EX);
        $data  = json_decode(stream_get_contents($fp) ?: '', true);
        $hour  = (int) (floor(time() / 3600) * 3600);

        if (!is_array($data) || ($data['hour'] ?? 0) !== $hour) {
            $data = ['hour' => $hour, 'count' => 0];
        }

        $data['count'] = (int) ($data['count'] ?? 0) + 1;
        $allowed = $data['count'] <= RATE_LIMIT_MAX;

        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, json_encode($data));
        fflush($fp);

        return $allowed;
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/**
 * Odstraní z e-mailu metadata, která by šla použít ke korelaci s přístupovými
 * záznamy webserveru nebo prozrazují prostředí serveru: přesný čas odeslání
 * (zaokrouhlí se na začátek hodiny), hostname serveru v Message-ID a HELO
 * a verzi PHPMailer v X-Mailer.
 */
function harden_mail(\PHPMailer\PHPMailer\PHPMailer $mail, string $domain): void
{
    $mail->XMailer     = false;   // PHPMailer 7: prázdný řetězec = výchozí hlavička, jiná hodnota = žádná
    $mail->Hostname    = $domain;
    $mail->MessageID   = '<' . bin2hex(random_bytes(16)) . '@' . $domain . '>';
    $mail->MessageDate = gmdate('D, d M Y H:00:00 +0000', (int) (floor(time() / 3600) * 3600));
}
