# Verifiering

Manuella manifest och instruktioner kontrollerade lokalt **2026-11-03**.
Företagets OpenShift-installation är ännu inte testad.

| Kontroll | Resultat |
| --- | --- |
| Go | 54 testfunktioner godkända med race detector. `go vet` godkänd. Runtime-koden är oförändrad i denna ändring. |
| Färdiga YAML | Deployment, Service, ConfigMap, Secret-skelett, ServiceAccounts och bootstrap accepterade med server-side dry-run mot lokalt Kubernetes-API efter att exempelvärden fyllts i. |
| Valfri Route | YAML läst och struktur kontrollerad. Lokala labbet saknar OpenShift Route-API, så servervalidering av routen återstår i OpenShift. |
| .env-import | Samma manuella kommando som i README användes med 11 fiktiva grundvärden. JSON, adresser och tokensträngar bevarades exakt i Secret. |
| Uppdatering | Upprepad applicering av Secret-skelettet raderade inga inlästa värden. Byte av token och tillägg/borttagning av driftkanalen verifierades. |
| PVC och callback | En replika, Recreate, befintlig PVC på `/data` och callback med poddens namespace kontrollerade. |
| Isolering | Tillfälligt lokalt testnamespace med enbart fiktiva värden skapades och togs bort. Ingen bot-Deployment installerades. Företagsklustret berördes inte. |
| Äldre hjälpskript | Eventuell generering går till ignorerade `deploy/local/` och skriver inte över de färdiga manifesten. Det manuella flödet i README använder inte skriptet. |

De oförändrade botfunktionerna testades även 2026-11-02: fem containerstarter
med samma Docker-volym, gammal/okänd databasstatus, återställningsbesked och
omstart utan upprepat driftinlägg. Containern kördes utan root och med read-only
rotfilsystem. Tidigare riktig lokal registry-push verifierades med simulerade
`oc`-svar; det ersätter inte kontroll av företagets registry och TLS.

Företagets ACS-roll, Mattermost-inställningar, nätverk, certifikat och verkliga
PVC behöver verifieras när ni installerar i labbet. Beställningar testas med
`/cve status`, `/cve scan` och `/cve schedule`.
