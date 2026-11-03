# Verifiering

Driftläget kontrollerat lokalt **2026-11-03**. Företagets OpenShift-installation
är ännu inte testad.

| Kontroll | Resultat |
| --- | --- |
| Go | 61 testfunktioner godkända med race detector. `go vet` godkänd. Även den tidigare uttryckliga modellen `per-user` täcks av regressionstester. |
| Driftmedlemmar | Status, skanning och rapport fungerar för en ny kanalmedlem utan användarmappning eller personliga klusterbehörigheter. |
| Scheman | Det inbyggda Mattermost-formuläret sparar scheman och provkör dem. Schemat fortsätter när skaparen lämnar kanalen och tidigare sparad delningspolicy fungerar i driftläget. |
| Kanalgräns | Andra kanaler, projekt utanför `SCAN_NAMESPACES`, icke-medlemmar, offentliga eller arkiverade kanaler och saknad botmedlem avvisas. |
| Kubernetes | Driftläget skapar ingen Kubernetes-API-klient. Den riktiga containern kördes utan API-token eller API-CA. Deployment och ServiceAccount har `automountServiceAccountToken: false`; inget RBAC-bootstrap behövs. |
| ConfigMap och Secret | Adresser, driftkanal, projektlista och callback hämtas från `cvebridge-config`. Tre tokenvärden läses från `cvebridge-tokens`. Ingen användarmappning eller `.env` behövs. En äldre all-in-one Secret påverkar inte konfigurationen. |
| Runtime | Ny Go-image byggd. Status, manuell skanning, rapport, öppna/spara schema och provkörning verifierade mot simulerade Mattermost/ACS-API:er över HTTPS med monterad CA. Inga personliga identitets-API-anrop gjordes. |
| CA-paket | Imagen innehåller inget eget CA-paket. Klustrets paket monteras skrivskyddat på `/ca`. Fel CA och fel värdnamn avvisades även när systemets separata CA-fil innehöll rätt utfärdare. |
| OpenShift-injektion | CA-innehållet fylldes uttryckligen av testet i lokala Kubernetes. Verklig automatisk injektion och företagets CA-kedjor återstår att verifiera i OpenShift. |
| YAML | ConfigMaps, token-Secret, Deployment, Service och ServiceAccount accepterade med server-side dry-run mot lokala Kubernetes efter att platshållare fyllts i. |
| Valfri Route | YAML och struktur kontrollerade tidigare. Lokala labbet saknar OpenShift Route-API; servervalidering återstår i OpenShift. |
| PVC och städning | En replika, Recreate och SQLite på `/data`. Tillfälligt testnamespace, testcontainer och testvolym togs bort. Företagets kluster har inte ändrats och inga riktiga Mattermost-meddelanden skickades. |

Företagets ACS-roll, kanalkonfiguration, registry, nätverk, CA-paket och PVC
behöver verifieras i ert labb. Kör `/cve status`, `/cve scan team-a` och
`/cve schedule` i den privata driftkanalen. `/healthz` är endast ett processtest.

Podman saknas i denna verifieringsmiljö. Imagen byggdes med samma Dockerfile
via Docker; ett riktigt Podman-bygge och registry-push återstår i er miljö.
