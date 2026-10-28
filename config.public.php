<?php
/**
 * Veřejná konfigurace — smí obsahovat jen údaje, které nejsou tajné.
 * Slouží i jako důkaz transparentnosti: hlášení se posílají přesně na adresu
 * `report_to`, odesílají se z účtu `smtp_from` přes server `smtp_host`.
 *
 * Tajné hodnoty (app_secret, smtp_pass, případně smtp_user) patří do
 * config.local.php (viz config.local.example.php). Soubor config.local.php
 * tyto hodnoty přepsat nesmí, jinak se aplikace nespustí.
 */
return [
    // Adresa, na kterou se doručují hlášení.
    'report_to' => 'whistleblowing@skolavdf.cz',

    // Odesílatel e-mailu (účet, ze kterého formulář hlášení odesílá).
    'smtp_from' => 'mailer@skolavdf.cz',
    'smtp_from_name' => 'Whistleblowing VDF',

    // SMTP server
    'smtp_host' => 'smtp.forpsi.com',
    'smtp_port' => 587,
    'smtp_secure' => 'tls',

    // Odkaz na veřejné úložiště se zdrojovým kódem aplikace (transparentnost).
    'github_url' => 'https://github.com/skolavdf-dev/whistleblowing',
];
