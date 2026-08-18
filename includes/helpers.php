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
 * IP adresa návštěvníka se nikde v aplikaci neloguje ani neukládá v čitelné
 * podobě — pro jemný rate limit se používá pouze nevratný, solený hash
 * s krátkou životností (viz check_rate_limit níže).
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

/**
 * Vygeneruje stateless anti-spam token (jednoduchá matematická úloha).
 * Podepsáno HMAC pomocí APP_SECRET — nelze podvrhnout ani přečíst
 * odpověď bez znalosti tajného klíče, a přitom nevyžaduje session.
 *
 * @return array{num1:int, num2:int, ts:int, sig:string}
 */
function captcha_generate(): array
{
    $num1 = random_int(1, 9);
    $num2 = random_int(1, 9);
    $ts   = time();
    $sig  = hash_hmac('sha256', "{$num1}:{$num2}:{$ts}", APP_SECRET);

    return ['num1' => $num1, 'num2' => $num2, 'ts' => $ts, 'sig' => $sig];
}

/**
 * Ověří anti-spam token a odpověď návštěvníka.
 * Kontroluje: platnost podpisu, stáří tokenu (ochrana proti botům, které
 * odešlou formulář okamžitě, i proti replayi starého tokenu) a správnost
 * výsledku.
 */
function captcha_verify(int $num1, int $num2, int $ts, string $sig, string $answer): bool
{
    $expectedSig = hash_hmac('sha256', "{$num1}:{$num2}:{$ts}", APP_SECRET);
    if (!hash_equals($expectedSig, $sig)) {
        return false;
    }

    $age = time() - $ts;
    if ($age < CAPTCHA_MIN_SECONDS || $age > CAPTCHA_MAX_SECONDS) {
        return false;
    }

    $answer = trim($answer);
    if ($answer === '' || !ctype_digit($answer)) {
        return false;
    }

    return (int) $answer === $num1 + $num2;
}

/**
 * Jemný rate limit proti hromadnému zahlcení formuláře.
 *
 * IP adresa se nikdy neukládá v čitelné podobě — použije se pouze
 * HMAC hash (solený APP_SECRET) jako jméno dočasného souboru s krátkou
 * životností (RATE_LIMIT_WINDOW). Soubor obsahuje jen počítadlo a čas,
 * nikdy obsah zprávy. Při jakémkoliv problému s úložištěm se ochrana
 * chová "fail-open" (radši propustit, než zablokovat oznamovatele).
 */
function check_rate_limit(): bool
{
    if (!RATE_LIMIT_ENABLED) {
        return true;
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($ip === '') {
        return true;
    }

    $dir = STORAGE_DIR . '/ratelimit';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return true;
    }

    $hash = substr(hash_hmac('sha256', $ip, APP_SECRET), 0, 24);
    $file = $dir . '/' . $hash . '.json';

    $fp = @fopen($file, 'c+');
    if ($fp === false) {
        return true;
    }

    try {
        flock($fp, LOCK_EX);
        $raw  = stream_get_contents($fp) ?: '';
        $data = json_decode($raw, true);
        $now  = time();

        if (!is_array($data) || !isset($data['start'], $data['count']) || ($now - (int) $data['start']) > RATE_LIMIT_WINDOW) {
            $data = ['start' => $now, 'count' => 0];
        }

        $data['count']++;
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
