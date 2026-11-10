# Sparat labbunderlag: ACS och basimages

Detta är en arkiverad kopia av test- och rapportarbetet den 10 november 2026.
Läs [molnöverlämningen](../../../CLOUD_HANDOFF.md) från repots rot för sammanhang.

`work/` innehåller ursprungliga skript, råa API-svar och loggar. `outputs/`
innehåller rapporter, samlad bevisning och bilder. Testets ursprungliga
live-skript kräver det tidigare lokala labbet och en API-hjälpare som inte
lagras i Git. De ska inte köras som molnsetup. Filerna kan innehålla
labbspecifika sökvägar, namespace- och image-ID:n; de innehåller inte labbets
autentisering.

`source-manifest.json` anger SHA256 för alla 81 överförda originalfiler.
Terminalutskrifterna `build.log` och `preload.log` har komprimerats till
`.log.gz` utan att innehållet ändrats; övriga originalfiler är byteidentiska.

Kör `python3 docs/lab-evidence/2026-11-10-acs-base-images/verify_evidence.py`
från repots rot för en kontroll utan nätverk eller klusteranslutning.
Kontrollen läser bevis; den återskapar inte live-testet.
