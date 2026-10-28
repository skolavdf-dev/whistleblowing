# Bezpečnostní politika

Jde o veřejný projekt, který chrání anonymitu oznamovatelů. Bezpečnostní chyby, zejména ty,
které by mohly prozradit odesílatele hlášení, **nehlaste veřejně** (issue, pull request, diskuse).

Použijte soukromé hlášení zranitelností na GitHubu (Security → Report a vulnerability).
Kontakt na správce školního webu: viz <https://www.skolavdf.cz>. Do hlášení prosím nevkládejte skutečná data oznamovatelů.

## Co do repozitáře nepatří

- `config.local.php`, hesla, klíče (adresy schránek a SMTP server patří do veřejného `config.public.php`)
- obsah složky `storage/`, logy, testovací hlášení, zálohy

Vzorová tajná konfigurace (`config.local.example.php`) smí obsahovat jen zástupné hodnoty.
Pokud se tajemství omylem dostane do repozitáře, je nutné ho okamžitě **změnit** (smazání commitu nestačí).
