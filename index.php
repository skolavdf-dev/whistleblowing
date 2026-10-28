<?php
declare(strict_types=1);

/**
 * index.php — anonymní whistleblowingový formulář
 *
 * Aplikace je záměrně jednoduchá: jeden soubor zpracuje formulář a pošle
 * e-mail, žádné MVC, žádné databáze, žádné session ani cookies. Cílem je,
 * aby byl kód snadno čitelný a ověřitelný komukoliv, kdo mu má důvěřovat —
 * proto je i veřejně na GitHubu (viz odkaz na stránce).
 *
 * Bezpečnostní opatření v tomto souboru:
 *   - žádné session/cookies → nic, co by šlo použít ke sledování návštěvníka
 *   - aplikace s IP adresou návštěvníka vůbec nepracuje (ani log, ani hash)
 *   - striktní bezpečnostní hlavičky (CSP, žádné inline skripty, no-referrer)
 *   - HMAC podepsaná jednorázová captcha + honeypot + globální rate limit
 *   - veškerý výstup do HTML prochází přes e() (ochrana proti XSS)
 *   - PHPMailer používá parametrizované API (addAddress/setFrom), žádné
 *     ruční skládání hlaviček → ochrana proti header/SMTP injection
 */

// Chybové výpisy PHP se nikdy nesmí zobrazit návštěvníkovi (mohly by
// prozradit cesty na serveru apod.) — nespoléháme na php.ini hostingu.
ini_set('display_errors', '0');
error_reporting(E_ALL);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

// ─── Bezpečnostní hlavičky ─────────────────────────────────────────────────
header_remove('X-Powered-By'); // nezveřejňovat verzi PHP

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');

// Stránka obsahuje formulář, který při chybě znovu vypíše to, co návštěvník
// napsal (včetně textu hlášení) — na sdíleném/veřejném počítači nesmí
// prohlížeč tuto odpověď ukládat do cache ani do zpět/vpřed historie.
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

// Nepovolujeme žádné prohlížečové funkce, které formulář nepotřebuje.
header(
    'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), ' .
    'usb=(), interest-cohort=(), browsing-topics=()'
);

if ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || ($_SERVER['SERVER_PORT'] ?? 80) == 443) {
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains');
}

header(
    "Content-Security-Policy: default-src 'none'; " .
    "style-src 'self'; " .
    "font-src 'self'; " .
    "img-src 'self' data:; " .
    "form-action 'self'; " .
    "object-src 'none'; " .
    "base-uri 'none'; " .
    "frame-ancestors 'none'; " .
    "upgrade-insecure-requests"
);

function sent_redirect(): never
{
    header('Location: index.php?odeslano=1', true, 303);
    exit;
}

$errors = [];
// Po úspěšném odeslání se přesměrujeme (303) na ?odeslano, aby obnovení stránky
// neodeslalo hlášení znovu. Adresa žádná data neobsahuje.
$sent   = $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['odeslano']);
$isSpam = false;

// Hodnoty pro znovu-vyplnění formuláře při chybě (nikdy needitujeme honeypot/captcha).
$in = [
    'message' => '',
    'name'    => '',
    'phone'   => '',
    'email'   => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Pole musí být řetězce (message[]=… apod. se odmítne) a platné UTF-8.
    $fields = [];
    foreach (['message', 'name', 'phone', 'email', 'company', 'num1', 'num2', 'ts', 'nonce', 'sig', 'captcha_answer'] as $key) {
        $fields[$key] = post_string($key);
    }
    $inputOk = !in_array(null, $fields, true);
    foreach ($fields as $value) {
        if ($value !== null && !is_utf8($value)) {
            $inputOk = false;
        }
    }

    $in['message'] = $inputOk ? clean_message($fields['message']) : '';
    $in['name']    = $inputOk ? clean_line($fields['name']) : '';
    $in['phone']   = $inputOk ? clean_line($fields['phone']) : '';
    $in['email']   = $inputOk ? clean_line($fields['email']) : '';

    // Honeypot — skryté pole, které vyplňují jen boti. Člověk ho nikdy neuvidí.
    $isSpam = $inputOk && trim($fields['company']) !== '';

    // Anti-spam captcha (stateless, HMAC podepsaná, jednorázová — viz includes/helpers.php).
    $captchaOk = $inputOk
        && ctype_digit($fields['num1'])
        && ctype_digit($fields['num2'])
        && ctype_digit($fields['ts'])
        && captcha_verify(
            (int) $fields['num1'],
            (int) $fields['num2'],
            (int) $fields['ts'],
            $fields['nonce'],
            $fields['sig'],
            $fields['captcha_answer']
        );

    if (!$isSpam) {
        if (!$inputOk) {
            $errors[] = 'Formulář obsahuje neplatná data. Zkuste to prosím znovu.';
        }
        if (!$captchaOk) {
            $errors[] = 'Ověřovací otázka nebyla vyplněna správně nebo formulář vypršel. Zkuste to prosím znovu.';
        }
        if ($inputOk) {
            if ($in['message'] === '') {
                $errors[] = 'Napište prosím text hlášení.';
            } elseif (mb_strlen($in['message']) > MAX_MESSAGE_LENGTH) {
                $errors[] = 'Text hlášení je příliš dlouhý (maximálně ' . MAX_MESSAGE_LENGTH . ' znaků).';
            }
            if (mb_strlen($in['name']) > MAX_NAME_LENGTH) {
                $errors[] = 'Jméno je příliš dlouhé.';
            }
            if ($in['phone'] !== '' && (mb_strlen($in['phone']) > MAX_PHONE_LENGTH || !preg_match('/^[0-9+\-\s()]+$/u', $in['phone']))) {
                $errors[] = 'Telefonní číslo obsahuje nepovolené znaky.';
            }
            if ($in['email'] !== '' && !filter_var($in['email'], FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Zadaný e-mail není platná e-mailová adresa.';
            }
        }
        // Globální limit se počítá až pro hlášení, která by se opravdu odeslala —
        // chybné pokusy ani boti ho nevyčerpají.
        if ($errors === [] && !check_rate_limit()) {
            $errors[] = 'Formulář je teď přetížený. Zkuste to prosím později.';
        }
    }

    if ($errors === []) {
        if ($isSpam) {
            // Botovi předstíráme úspěch, ale zprávu neposíláme.
            sent_redirect();
        } else {
            $bodyLines   = [];
            $bodyLines[] = 'Zpráva:';
            $bodyLines[] = $in['message'];
            $bodyLines[] = '';
            $bodyLines[] = '---';
            $bodyLines[] = 'Kontaktní údaje (nepovinné, uvedl je odesílatel dobrovolně):';
            $bodyLines[] = 'Jméno: ' . ($in['name'] !== '' ? $in['name'] : '— neuvedeno —');
            $bodyLines[] = 'Telefon: ' . ($in['phone'] !== '' ? $in['phone'] : '— neuvedeno —');
            $bodyLines[] = 'E-mail: ' . ($in['email'] !== '' ? $in['email'] : '— neuvedeno —');
            $plainBody   = implode("\n", $bodyLines);

            $template    = (string) file_get_contents(__DIR__ . '/templates/mail.html');
            $htmlContent = nl2br(e($plainBody));
            $htmlBody    = str_replace('{content}', $htmlContent, $template);

            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host       = SMTP_HOST;
                $mail->Port       = SMTP_PORT;
                $mail->SMTPAuth   = true;
                $mail->Username   = SMTP_USER;
                $mail->Password   = SMTP_PASS;
                $mail->SMTPSecure = SMTP_SECURE;
                $mail->CharSet    = 'UTF-8';
                harden_mail($mail, MAIL_DOMAIN);

                $mail->setFrom(SMTP_FROM, SMTP_FROM_NAME);
                $mail->addAddress(REPORT_TO_EMAIL);

                // Reply-To nastavíme jen pokud odesílatel dobrovolně uvedl e-mail.
                if ($in['email'] !== '') {
                    $mail->addReplyTo($in['email'], $in['name'] !== '' ? $in['name'] : '');
                }

                $mail->isHTML(true);
                $mail->Subject = REPORT_SUBJECT;
                $mail->Body    = $htmlBody;
                $mail->AltBody = $plainBody;

                $mail->send();
            } catch (PHPMailerException $e) {
                // Návštěvníkovi chybu nezobrazujeme (mohla by prozradit interní info).
                // Správce se ale musí dozvědět, že hlášení nedoputovala — do logu jde jen
                // obecná zpráva, nikdy obsah hlášení ani údaje odesílatele.
                error_log('whistleblowing: odeslání e-mailu selhalo (' . get_class($e) . ')');
                $errors[] = 'Odeslání se bohužel nezdařilo. Zkuste to prosím později.';
            }
            if ($errors === []) {
                sent_redirect();
            }
        }
    }
}

// Formulář je nutné znovu vyrenderovat s novým anti-spam tokenem
// (starý token je jednorázový vůči časové kontrole a nemá smysl ho recyklovat).
$captcha = captcha_generate();
?>
<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Whistleblowing — VOŠ, SPŠ a SOŠ Varnsdorf</title>
<meta name="description" content="Anonymní formulář pro nahlášení podezření na protiprávní nebo neetické jednání ve škole.">
<link rel="icon" href="favicon.ico" sizes="any">
<link rel="stylesheet" href="assets/fonts/fonts.css">
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

<header>
    <div class="container">
        <a class="brand" href="index.php">
            <svg class="brand-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 866" aria-hidden="true">
                <polygon points="0 0 500 0 500 188 326 188 0 0" fill="#ffd400" />
                <polygon points="0 0 326 188 413 339 250 433 0 0" fill="#ffea80" />
                <polygon points="500 0 1000 0 674 188 500 188 500 0" fill="#41d7ff" />
                <polygon points="674 188 1000 0 750 433 587 339 674 188" fill="#00c0f3" />
                <polygon points="250 433 413 339 500 490 500 866 250 433" fill="#c2dd78" />
                <polygon points="500 490 587 339 750 433 500 866 500 490" fill="#a6ce39" />
            </svg>
            <span class="brand-text">VOŠ | SPŠ | SOŠ<br><span>Varnsdorf</span></span>
        </a>
    </div>
</header>

<main>
<div class="container">

<section class="panel">
    <h1>Whistleblowing</h1>
    <p class="lead">
        Tento formulář slouží k nahlášení podezření na protiprávní, neetické nebo jinak nevhodné
        jednání v souvislosti se školou. Vaše hlášení bude odesláno na
        <a href="mailto:<?= e(REPORT_TO_EMAIL) ?>"><?= e(REPORT_TO_EMAIL) ?></a>.
    </p>
    <ul class="info-list">
        <li>Aplikace <strong>nezjišťuje ani neukládá vaši IP adresu</strong>, nepoužívá cookies ani jiné sledovací technologie. Provozovatel webového serveru ale může běžně zaznamenávat technické přístupové záznamy — viz „Podrobněji o anonymitě“.</li>
        <li>Jméno, telefon a e-mail jsou <strong>zcela dobrovolné</strong>. Uveďte je jen tehdy, chcete-li být kontaktováni ohledně dalšího šetření.</li>
        <li>Aby byla anonymita důvěryhodná, je zdrojový kód této aplikace veřejně k nahlédnutí<?php if (GITHUB_REPO_URL !== ''): ?> na
            <a href="<?= e(GITHUB_REPO_URL) ?>" target="_blank" rel="noopener noreferrer">GitHubu</a><?php endif; ?> —
            kdokoliv si může ověřit, že se zprávou nakládáme přesně tak, jak popisujeme.</li>
    </ul>

    <details class="info-details">
        <summary>Podrobněji o anonymitě a bezpečnosti</summary>
        <div class="info-details-body">
            <h3>Jak zajišťujeme anonymitu</h3>
            <ul class="info-list">
                <li>Stránka <strong>nepoužívá cookies ani přihlašování</strong> a aplikace si neukládá vaši IP adresu (ani její hash). Součástí hlášení tak není nic, podle čeho by šlo odesílatele určit, pokud to sami neuvedete v textu nebo v kontaktních údajích.</li>
                <li>Nic se nenačítá z cizích serverů (žádné reklamní ani sledovací skripty, ani třeba běžné písmo z Google) — i to by mohlo prozradit, že jste stránku navštívili.</li>
                <li>Stránka nepoužívá žádný JavaScript. Menší plocha pro chyby a nic se neděje „potichu" na pozadí mimo samotné odeslání formuláře.</li>
                <li>Odkaz na tento web nikam „neprosakuje" — když kliknete na odkaz na GitHub, cílová stránka se nedozví, že jste přišli odsud.</li>
            </ul>
            <h3>Jak formulář chráníme před zneužitím</h3>
            <ul class="info-list">
                <li>Proti spamu používáme jen vlastní jednoduché mechanismy (skryté pole pro roboty, časová kontrola, ověřovací otázka) — žádnou cizí captcha službu, která by mohla sledovat návštěvníky.</li>
                <li>Počet hlášení je omezen jen <strong>celkově za hodinu pro celý formulář</strong>, aby ho nešlo zahltit. Formulář si o jednotlivých návštěvnících nic nepamatuje a omezení se neváže na obsah žádné zprávy.</li>
                <li>Text hlášení se do e-mailu vkládá bezpečně, takže ho nelze zneužít k manipulaci s odesílaným e-mailem.</li>
            </ul>
            <h3>Co pro vlastní bezpečí můžete udělat vy</h3>
            <ul class="info-list">
                <li>Obsah hlášení může nechtěně prozradit vaši identitu (styl psaní, konkrétní detaily) — technická ochrana toto nevyřeší, zvažte proto sami, co je bezpečné napsat.</li>
                <li>Pokud chcete nejvyšší možnou anonymitu, zvažte odeslání z jiné než školní sítě.</li>
                <li>Provozovatel serveru (hosting) může technicky vidět běžné přístupové záznamy webserveru (IP adresa a čas přístupu) — to tato aplikace neřídí. Také provozovatel vaší sítě (např. školní síť) může vidět, že jste tuto stránku navštívili.</li>
                <li>E-mail s hlášením neobsahuje přesný čas odeslání (je zaokrouhlen na celou hodinu) ani jméno serveru.</li>
                <li>Hlášení se odesílá vždy jen na adresu <?= e(REPORT_TO_EMAIL) ?> ze schránky <?= e(SMTP_FROM) ?> přes server <?= e(SMTP_HOST) ?><?php if (GITHUB_REPO_URL !== ''): ?>; toto nastavení je veřejné v souboru <a href="<?= e(GITHUB_REPO_URL) ?>/blob/main/config.public.php" target="_blank" rel="noopener noreferrer">config.public.php</a><?php endif; ?>.</li>
            </ul>
            <p class="muted">
                Celý zdrojový kód aplikace, včetně těchto bezpečnostních opatření, je veřejně k nahlédnutí<?php if (GITHUB_REPO_URL !== ''): ?>
                na <a href="<?= e(GITHUB_REPO_URL) ?>" target="_blank" rel="noopener noreferrer">GitHubu</a><?php endif; ?>.
            </p>
        </div>
    </details>
</section>

<?php if ($sent): ?>

<section class="panel">
    <div class="alert alert-success">
        <strong>Děkujeme.</strong> Hlášení bylo odesláno.
    </div>
    <a class="btn btn-secondary" href="index.php">Odeslat další hlášení</a>
</section>

<?php else: ?>

<section class="panel">
    <?php if ($errors !== []): ?>
    <div class="alert alert-error">
        <strong>Formulář se nepodařilo odeslat:</strong>
        <ul>
            <?php foreach ($errors as $err): ?>
            <li><?= e($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>

    <form method="post" novalidate autocomplete="off">
        <!-- Honeypot: pole skryté pro lidské oči i čtečky obrazovky, boti ho ale často vyplní. -->
        <div class="hp-field" aria-hidden="true">
            <label for="company">Nevyplňujte toto pole</label>
            <input type="text" id="company" name="company" tabindex="-1" autocomplete="off" value="">
        </div>

        <input type="hidden" name="num1" value="<?= (int) $captcha['num1'] ?>">
        <input type="hidden" name="num2" value="<?= (int) $captcha['num2'] ?>">
        <input type="hidden" name="ts" value="<?= (int) $captcha['ts'] ?>">
        <input type="hidden" name="nonce" value="<?= e($captcha['nonce']) ?>">
        <input type="hidden" name="sig" value="<?= e($captcha['sig']) ?>">

        <div class="form-group">
            <label for="message">Text hlášení</label>
            <textarea id="message" name="message" required
                      maxlength="<?= MAX_MESSAGE_LENGTH ?>"
                      placeholder="Popište prosím co nejkonkrétněji, co se stalo, kdy a kde…"><?= e($in['message']) ?></textarea>
        </div>

        <h2>Kontaktní údaje <span class="label-optional">(nepovinné)</span></h2>
        <div class="form-row cols-3">
            <div class="form-group">
                <label for="name">Jméno</label>
                <input type="text" id="name" name="name" maxlength="<?= MAX_NAME_LENGTH ?>" value="<?= e($in['name']) ?>">
            </div>
            <div class="form-group">
                <label for="phone">Telefon</label>
                <input type="tel" id="phone" name="phone" maxlength="<?= MAX_PHONE_LENGTH ?>" value="<?= e($in['phone']) ?>">
            </div>
            <div class="form-group">
                <label for="email">E-mail</label>
                <input type="email" id="email" name="email" value="<?= e($in['email']) ?>">
            </div>
        </div>

        <div class="form-footer">
            <div class="form-group captcha-row">
                <label for="captcha_answer" class="captcha-question">
                    Ověření: kolik je <?= (int) $captcha['num1'] ?> + <?= (int) $captcha['num2'] ?>?
                </label>
                <input type="text" id="captcha_answer" name="captcha_answer" inputmode="numeric" required autocomplete="off" value="">
            </div>
            <button type="submit" class="btn btn-primary">Odeslat hlášení</button>
        </div>
    </form>
</section>

<?php endif; ?>

</div>
</main>

<footer>
    <div class="container">
        <p>
            VOŠ, SPŠ a SOŠ Varnsdorf ·
            <?php if (GITHUB_REPO_URL !== ''): ?>
            <a href="<?= e(GITHUB_REPO_URL) ?>/releases" target="_blank" rel="noopener noreferrer">v<?= e(APP_VERSION) ?></a> ·
            <a href="<?= e(GITHUB_REPO_URL) ?>" target="_blank" rel="noopener noreferrer">zdrojový kód na GitHubu</a>
            <?php else: ?>
            v<?= e(APP_VERSION) ?>
            <?php endif; ?>
        </p>
    </div>
</footer>

</body>
</html>
