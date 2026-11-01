# Från .env till en bot i ditt OpenShift-namespace

## 1. Förbered anslutningarna

ACS Central, Scanner och Sensor ska redan fungera för det valda klustret.
Mattermost-servern ska kunna nå botens HTTPS-route. Boten ska kunna nå Mattermost,
Central och Kubernetes API. Tillåt nödvändig trafik i företagets befintliga brandvägg
eller NetworkPolicy. Servern som kör Mattermost måste kunna skicka dialog-callbacks
också; en sida som bara går att öppna från din laptop räcker inte.

Skapa ett vanligt Mattermost-botkonto, aktivera botkonton och personliga bot-tokens
enligt era regler, och bjud in boten till teamets **privata kanal**. Använd inte en
systemadministratörs token. Hämta botens ID, kanalens ID och teammedlemmarnas stabila
användar-ID:n via Mattermost/API eller integrationsansvarig.

Registrera en **Custom Slash Command** i teamets integrationsinställningar:

| Fält | Värde |
| --- | --- |
| Command Trigger Word | `cve` |
| Request URL | `https://DIN-BOT-ROUTE/slash/cve` |
| Request Method | `POST` |
| Autocomplete | Aktiverat, exempel: `scan [namespace]`, `schedule`, `status` |

Kopiera kommandots token till `MATTERMOST_COMMAND_TOKEN` i `.env`. Request URL ska
vara samma HTTPS-origin som `WEBHOOK_PUBLIC_URL` plus `/slash/cve`. När boten har
startat öppnar `/cve schedule` ett formulär direkt i Mattermost. Ingen extra
aktivering per kanal behövs utöver godkänd kanal i konfigurationen och botmedlemskap.
Ett eventuellt `/acs` registreras separat med egen token i
`MATTERMOST_ACS_COMMAND_TOKEN` och samma Request URL.

Mattermost-administratören kan behöva tillåta slash-kommandon och serveranslutning
till en intern botadress. Begränsa eventuell intern adresslista till botens faktiska
adress enligt era regler. Vanliga teammedlemmar behöver ingen adminroll för att köra.

## 2. Fyll i en enda .env

```sh
./cvebridge.sh init
```

Öppna `.env` och ersätt mallvärdena. Fyll framför allt i:

- `NAMESPACE`: botens installationsnamespace.
- `APP_IMAGE`: hela registry/repo:version, till exempel `registry.foretag.se/team/cvebridge:1.0.0`
 .
- `WEBHOOK_PUBLIC_URL`: botens planerade HTTPS-route, utan sökväg eller avslutande `/`.
- Mattermost-adress, bot-ID, bot-token och slash-token.
- Kanal-ID → godkända namespaces samt användar-ID → exakta OpenShift-användarnamn.
- Godkända schemanamespaces, ansvariga personer och `SCHEDULE_SERVICE_USER` som
  `system:serviceaccount:DITT_NAMESPACE:cvebridge-reporter`.
- Central-adress och det **exakta ACS-kluster-ID:t**, inte visningsnamnet.
- Läs-, scan-, status- och schematoken med de ACS-rättigheter funktionen behöver.
  Ge schematoken endast godkänd omfattning. Boten kan inte skapa eller utöka dessa rättigheter.
- Scannerkomponenten `SCANNER_V4` eller `SCANNER` som ni faktiskt använder.
- Sökväg till företagets publika CA-PEM om Central eller Mattermost använder privat CA.
- `IMAGE_PULL_SECRET` om klustret behöver en registry-secret, och vid behov `STORAGE_CLASS`.

JSON-mapparna ska ha samma kanal-ID där samma kanal avses. Lägg till alla mänskliga
medlemmar i användarmappen. Exempel:

```dotenv
MATTERMOST_CHANNEL_SCOPES='{"KANALENS_26_TECKEN_LANGA_ID":["team-a"]}'
MATTERMOST_KUBE_USER_MAP='{"ANVANDARENS_26_TECKEN_ID":"exakt-klusteranvandare"}'
```

Ovan är förklarande platshållare; riktiga Mattermost-ID:n har exakt 26 gemener/siffror.
Värden läses som data; `$(...)`, backticks och `$VAR` körs/expanderas aldrig.
Behåll `.env` privat. Tokens ska inte läggas i Dockerfile, Git, README eller LinkedIn.

## 3. Bygg och pusha din image

```sh
docker login DIN_REGISTRY
./cvebridge.sh build
./cvebridge.sh push
./cvebridge.sh render
```

För Podman: `export CONTAINER_ENGINE=podman` och `podman login DIN_REGISTRY`.
Imagen innehåller Go-boten. Samma image kan användas i olika miljöer med olika `.env`.
Rendering kontrollerar inställningarna och skapar två filer med privata filrättigheter:

- `deploy/generated/bootstrap.yaml`: namespace och kluster-/namespace-behörigheter.
- `deploy/generated/deployment.yaml`: ServiceAccounts, Secret, ConfigMap, PVC,
  Deployment med din image, Service och OpenShift Route.

Filerna är Kubernetes List i JSON-format, vilket är giltig YAML och kan läsas av `oc apply`.
CA-filer läses från datorn vid rendering. Du behöver Go endast om du bygger/testar
binären direkt; huvudflödet använder containerverktyget.

## 4. Logga in och låt plattformsteamet godkänna bootstrap en gång

```sh
oc login https://api.DITT-KLUSTER:6443
oc whoami
oc config current-context
```

Kontrollera att det är ditt avsedda labb. En behörig plattformsadministratör granskar
och applicerar `bootstrap.yaml` en gång. Den innehåller:

- Ett dedikerat installationsnamespace.
- ClusterRole/Binding som låter appkontot skapa **SubjectAccessReview**.
  Det ger ingen generell läsbehörighet till workloads.
- Reporter-Role/Binding i uttryckligen godkända schemanamespaces, endast `list deployments`.
  Dessa mål-namespaces ska redan finnas, om de inte är installationsnamespacet.

```sh
oc apply -f deploy/generated/bootstrap.yaml
```

En vanlig namespace-admin kan inte själv skapa klusterbehörigheterna. Om namespace
redan finns enligt företagets standard kan plattformsteamet skapa det med sina
vanliga etiketter/kvoter och granska bort Namespace-objektet ur bootstrap-filen.
Botens användarmapp ger inga Kubernetes-behörigheter. Mappade människor behöver
redan ha godkänd, direkt användarbaserad rätt att lista deployments i sina namespaces.
Gruppbaserade rättigheter antas inte av boten.

## 5. Applicera din Deployment

```sh
oc project DITT_NAMESPACE
# Vid privat registry: skapa registry-secret enligt företagets rutin först.
oc apply -f deploy/generated/deployment.yaml
oc rollout status deployment/cvebridge
oc get pods,pvc,svc,route
oc logs deployment/cvebridge -c bot --tail=50
```

Boten ska nu vara igång. `Pending` PVC behöver lagringskontroll.
`ImagePullBackOff` betyder att registry-adress, image eller pull-secret behöver kontrolleras.
En otillgänglig webhook-route ger ofta kommandofel innan boten ens ser förfrågan.

## 6. Kontrollera från Mattermost

```text
/cve help
/cve status
/cve scan team-a
/cve schedule
```

Kontrollera att scan ger en ny rapport med rätt namespace, **Åtgärd** och JSON-bilaga.
I schemadialogen: välj vardagar, `08:00`, `Europe/Stockholm`, rätt namespace,
**Ny skanning och rapport**, **Aktiverat**, **Spara inställningar**, sedan **Utför**.
Öppna igen och välj **Provkör sparat schema**. Läs sedan körhistoriken.
Testa även att ett konto utan godkänd mapping eller namespace-behörighet nekas.

Ingen separat webbplats behövs. Om du ser `failed to fetch`/kommandofel: kontrollera
Mattermost-serverns åtkomst till request URL och callback-adressen, route/TLS,
slash-token och botlogg. En lyckad `/healthz` är bara ett processtest.
