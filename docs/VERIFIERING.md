# Verifiering

ConfigMap/Secret-flödet kontrollerat lokalt **2026-11-03**.
Företagets OpenShift-installation är ännu inte testad.

| Kontroll | Resultat |
| --- | --- |
| Go | 54 testfunktioner godkända med race detector. `go vet` godkänd. Runtime-koden är oförändrad i denna ändring. |
| ConfigMap | Adresser, kanal-ID, JSON-mappning, app-namespaces och callback hämtas från `cvebridge-config`. Inga tokenfält finns i mallen. |
| Secret | `cvebridge-tokens` innehåller bara de tre grundtokenvärdena. Mallen använder `stringData`; ifylld `secret.yaml` är git-ignorerad. |
| Runtime | Den riktiga Go-containern startades med värden lästa från ConfigMap och Secret i lokala Kubernetes. Ingen `.env` eller import av miljöfil användes. Hälsokontroll och databasstatusinlägg till simulerat Mattermost godkända. |
| Uppdatering | En äldre `cvebridge-integration` med motstridiga adresser och namespace-lista låg kvar under testet. Deployment läser endast den nya token-Secret, så ConfigMap-värdena användes korrekt. |
| Färdiga YAML | Deployment, Service, ConfigMap, Secret, ServiceAccounts och bootstrap accepterade med server-side dry-run mot lokalt Kubernetes-API efter att exempelvärden fyllts i. |
| Valfri Route | YAML läst och struktur kontrollerad vid tidigare verifiering. Lokala labbet saknar OpenShift Route-API; servervalidering återstår i OpenShift. |
| PVC och callback | En replika, Recreate och befintlig PVC på `/data`. Callback läses från ConfigMap och namespace från poddens metadata. |
| Isolering | Tillfälligt lokalt testnamespace, testcontainer och testvolym togs bort. Företagets kluster har inte ändrats och inga verkliga Mattermost-meddelanden skickades. |

Tidigare kontroller omfattar beständig databas och omstart, larm vid gammal eller
okänd databasstatus, återställningsbesked, manuell skanning, CVE-sökning och
Mattermosts schemaformulär. Runtime-koden för dessa funktioner är oförändrad.

Företagets ACS-roll, Mattermost-inställningar, registry, nätverk, certifikat och
verkliga PVC behöver verifieras när ni installerar i labbet. Testa med
`/cve status`, `/cve scan` och `/cve schedule`.

Podman-kommandona i README har kontrollerats mot officiell dokumentation.
Podman finns inte i denna verifieringsmiljö; ett riktigt Podman-bygge och
registry-push behöver därför köras i er miljö. Hjälpskriptets befintliga
workflow-tester är godkända efter byte av förvald motor.
