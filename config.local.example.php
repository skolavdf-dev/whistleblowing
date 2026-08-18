<?php
/**
 * Zkopírujte jako config.local.php a doplňte hodnoty.
 * Soubor config.local.php NIKDY necommitujte (je v .gitignore).
 */
return [
    // Tajný klíč pro podepisování anti-spam tokenů (HMAC).
    // Vygenerujte např. příkazem: php -r "echo bin2hex(random_bytes(32));"
    'app_secret' => 'ZDE_VLOZIT_NAHODNY_TAJNY_RETEZEC',

    // Adresa, na kterou se doručují hlášení.
    'report_to' => 'whistleblowing@skolavdf.cz',

    // Odkaz na veřejné úložiště se zdrojovým kódem aplikace (transparentnost).
    'github_url' => 'https://github.com/skolavdf-dev/whistleblowing',

    // SMTP konfigurace
    'smtp_host' => 'smtp.forpsi.com',
    'smtp_port' => 587,
    'smtp_user' => 'mailer@skolavdf.cz',
    'smtp_pass' => 'HESLO',
    'smtp_from' => 'mailer@skolavdf.cz',
    'smtp_from_name' => 'Whistleblowing VDF',
    'smtp_secure' => 'tls',

    // Volitelné přepsání limitů (viz config.php pro výchozí hodnoty)
    // 'rate_limit_max'    => 5,
    // 'rate_limit_window' => 3600,
];
