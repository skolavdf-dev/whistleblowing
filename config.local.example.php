<?php
/**
 * Zkopírujte jako config.local.php a doplňte hodnoty.
 * Soubor config.local.php NIKDY necommitujte (je v .gitignore).
 *
 * Obsahuje JEN tajné a provozní hodnoty. Adresát, odesílatel a SMTP server
 * jsou veřejné a patří do config.public.php — zde je uvádět nesmíte
 * (aplikace by se nespustila).
 *
 * Doporučení: uložte skutečný soubor MIMO DocumentRoot a jeho cestu předejte
 * proměnnou prostředí WB_CONFIG (např. SetEnv WB_CONFIG /cesta/mimo/web/wb.php,
 * na IIS v nastavení aplikace/FastCGI).
 */
return [
    // Tajný klíč pro podepisování anti-spam tokenů (HMAC).
    // Vygenerujte např. příkazem: php -r "echo bin2hex(random_bytes(32));"
    'app_secret' => 'ZDE_VLOZIT_NAHODNY_TAJNY_RETEZEC',

    // Přihlášení k SMTP. Přihlašovací jméno je volitelné: pokud se liší od
    // adresy odesílatele (smtp_from), uveďte ho zde, jinak se použije smtp_from.
    'smtp_user' => 'SMTP_UZIVATEL',
    'smtp_pass' => 'SMTP_HESLO',

    // Volitelné
    // 'storage_dir'    => '/cesta/mimo/web/wb-storage', // zapisovatelný adresář (mimo DocumentRoot)
    // 'rate_limit_max' => 30,                           // hlášení za hodinu celkem (bez ohledu na IP)
];
