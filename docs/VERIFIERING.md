# Verifiering

Kontrollerat lokalt 2026-11-02. Företagets OpenShift-installation är ännu inte testad.

| Kontroll | Resultat |
| --- | --- |
| Go | 54 testfunktioner godkända med race detector. `go vet` godkänd. |
| Konfiguration | Grundfilen har 11 fält. Gemensam ACS-token används för alla botuppgifter; uttryckliga token-undantag fungerar och ofullständiga undantag nekas. |
| Container | Go-imagen byggd med vanlig `docker build -t cvebridge:local .`. `.env` ingår inte i byggkontexten. |
| Lokalt registry | Riktigt lokalt Distribution-registry:3: hjälpskriptet taggar, loggar in med token på stdin, pushar och verifierar taggen i registryt. `oc`-svaren simulerades. |
| YAML | Separata vanliga YAML-filer för Deployment, Service, ConfigMap, Secret och ServiceAccounts. Klusterbehörigheter ligger i separat bootstrap. Filerna har rättighet 0600. |
| Kubernetes | Genererade resurser accepterade med server-side dry-run i lokala labbet. Inga resurser installerades. |
| PVC | Färdig PVC refereras i Deployment. Ingen PV, PVC eller lagrings-Secret skapas i det läget. Databasen monteras på `/data`. |
| Felvägar | Saknad image, projekt, PVC, registry-route och felaktig konfiguration stoppar flödet före push. Hemligheter skrivs inte i inloggningens argument. |
| Driftbevakning | Timkontroll, daglig status, gammal/okänd status, återställning, leveransfel och separerad driftkanal verifierade mot simulerade tjänster. ACS-timeout lämnar tid för varningsleverans. |
| Container och omstart | Den körande nya imagen verifierad utan root och med read-only rotfilsystem. Samma Docker-volym behöll larmstatus genom fem containerstarter. Grön status, varning, okänd status och återställning levererades till simulerat Mattermost. |

Det tillfälliga registryt togs bort efter kontrollen. Företagets registry, TLS,
åtkomsträttigheter, ACS-roll och verkliga PVC-montering behöver verifieras i labbet.
Driftbevakningen har inte aktiverats mot företagets ACS eller Mattermost.

Den tidigare Go-versionen har också genomgått 11 riktiga Mattermost/ACS-kontroller:
manuell skanning, CVE-sökning, formulär och provkörning av schema. Den kontrollen
omfattade Åtgärd-rader, JSON-bilagor, nya skanntider och bevarat schema. En äldre
Go-image har verifierats med read-only rotfilsystem och samma beständiga SQLite-fil
under två olika icke-root-UID:n. Dessa tidigare tester ersätter inte verifiering
av den nya installationen i er miljö.
