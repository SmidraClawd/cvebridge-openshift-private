<div align="center">

# CVEBridge · privat OpenShift-leverans

**Från CVE till åtgärd. Direkt i Mattermost.**

[Installera](START_HAR.md) · [Fyll i .env](docs/ENV_VARDEN.md) · [Drift](docs/DRIFT.md)

</div>

Go-boten kopplar ACS/StackRox till Mattermost. Teamet kan starta skanningar,
söka en CVE och planera rapporter i kanalen. Resultatet visar prioriterade fynd,
**Åtgärd** och en JSON-bilaga med detaljer.

![Kompakt CVE-rapport i Mattermost](assets/reports/04-skanningsrapport.jpg)

## Från projekt till körande bot

1. Fyll i `.env` med era adresser, tokens, konton och namespaces.
2. Logga in i OpenShift och välj ett befintligt projekt.
3. Bygg och pusha imagen med `./cvebridge.sh build` och `./cvebridge.sh push`.
4. Generera installationen med `./cvebridge.sh render`.
5. Låt plattformsteamet applicera bootstrap en gång och applicera sedan Deployment.
6. Registrera Request URL för `/cve` och prova i Mattermost.

Kommandon och förutsättningar finns i [START_HAR.md](START_HAR.md).
Företagsvärden fylls i lokalt; `.env` och genererade Secret-filer ska inte committas.

## Adresserna i ditt kluster

| Del | Adress / funktion |
| --- | --- |
| Deployment-image | `image-registry.openshift-image-registry.svc:5000/<namespace>/cvebridge:<automatisk-tagg>` |
| Bot | `http://cvebridge-webhook.<namespace>.svc:8001` — räknas ut automatiskt. |
| ACS Central | `STACKROX_URL` — Central-adressen som boten kan nå. |
| Labbklustret | `STACKROX_CLUSTER_ID` — rätt klusters ID i ACS. |

**Sensor skickar klusterdata till Central. Boten använder Centrals API för
skanningar och CVE-resultat, och labbets Kubernetes-API för behörighetskontroll.**
Central kan finnas i samma kluster eller ett annat. `.svc`-adresser fungerar inom
klustrets nätverk; byt Central-adress om Central ligger någon annanstans.
Mattermost måste kunna nå botens interna Service. Push från en dator utanför
klustret använder registryts externa route när intern DNS inte är åtkomlig.

## Använd i Mattermost

| Kommando | Vad teamet får |
| --- | --- |
| `/cve scan team-a` | Ny skanning och rapport i den godkända privata kanalen. |
| `/cve CVE-2021-44228 team-a` | Fynd för just den CVE:n i aktiva poddars images. |
| `/cve schedule` | Formulär för dagar, tider och namespaces direkt i Mattermost. |
| `/cve status` | Status för CVE-databasens aktualitet. |

<details>
<summary>Visa schemaformuläret</summary>

![Schemaformulär i Mattermost](assets/native-schedule/01-schema-i-mattermost.jpg)

</details>

Bilderna är referenser från det tidigare Mattermost-labbet. Den aktuella Go-versionen
har också provats mot riktig Mattermost och ACS i det lokala labbet.

## Teknik och status

Go · Mattermost API · ACS Central API · Kubernetes RBAC · SQLite på PVC.
En vanlig Deployment med en replika; beställare och kanalåtkomst kontrolleras.

32 Go-testfunktioner med race detector, `go vet` och containerbygge är godkända.
Företagets OpenShift-installation behöver fortfarande verifieras i ert labb.
Se [verifiering](docs/VERIFIERING.md) och [arkitektur](docs/ARKITEKTUR.md).
