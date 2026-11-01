# Starta Go-boten i OpenShift med få fält

## 1. Logga in och välj installationsnamespace

```sh
oc login https://api.DITT-KLUSTER:6443
oc whoami
oc project cvebridge
```

Namespace `cvebridge` ska redan finnas. Om du har rätt att skapa projekt kan du
skapa det med `oc new-project cvebridge`; annars gör plattformsteamet det enligt
er vanliga rutin. Byt `NAMESPACE` i `.env` om ni använder ett annat namespace.
Du behöver push-behörighet till projektets registry, normalt `system:image-builder`.
ACS Central, Scanner och Sensor ska redan fungera för det valda klustret.

## 2. Fyll i den korta .env

```sh
./cvebridge.sh init
```

Öppna `.env`. Den har **12 företagsvärden att fylla i** och ett förvalt namespace:

| Fält | Vad du fyller i |
| --- | --- |
| `WEBHOOK_PUBLIC_URL` | Botens planerade HTTPS-route, utan sökväg eller avslutande `/`. |
| `MATTERMOST_INTERNAL_URL` | Adressen boten använder för att nå Mattermost. |
| `MATTERMOST_BOT_TOKEN` | Token för ett vanligt botkonto utan adminroll. |
| `MATTERMOST_COMMAND_TOKEN` | Token för slash-kommandot `/cve`. |
| `MATTERMOST_CHANNEL_ID` | Den godkända privata kanalens stabila ID, 26 tecken. |
| `SCAN_NAMESPACES` | Namespace-namn separerade med komma, till exempel `team-a,team-b`. |
| `MATTERMOST_KUBE_USER_MAP` | Stabila Mattermost-ID:n → exakta OpenShift-konton för människorna i kanalen. |
| `STACKROX_CLUSTER_ID` | ACS-klustrets exakta ID, inte visningsnamnet. |
| `STACKROX_TOKEN` | Token för läsning av inventering och fynd. |
| `STACKROX_SCAN_TOKEN` | Token för manuellt beställda skanningar. |
| `STACKROX_STATUS_TOKEN` | Token som får läsa CVE-databasens status. |
| `STACKROX_SCHEDULE_TOKEN` | Token med endast godkänd omfattning för automatiska körningar. |

De separata ACS-token behåller respektive funktions behörighetsgräns. Användarmappen
ger inga nya Kubernetes-behörigheter; användarna behöver redan godkänd, direkt
användarbaserad rätt att lista deployments i sina namespaces. Grupper gissas inte.

Du behöver inte ange imageadress, push-route, bot-ID eller samma kanal/namespaces
flera gånger. Standardvärden är:

- Deployment-image: `image-registry.openshift-image-registry.svc:5000/NAMESPACE/cvebridge:go-GITREVISION`.
  Utan Git räknas en stabil tagg ut från projektfilerna.
- Push-adress: hämtas med `oc get route default-route -n openshift-image-registry`.
- Central: `https://central.stackrox.svc:443`, scanner `SCANNER_V4`.
- Schema använder samma godkända kanal och namespaces. Det startar först när ni sparar schemat.
- Delningspolicy `common`, tidszon `Europe/Stockholm`, CVE-larmgräns 9 och första rapport utan ping.
- Rapporteridentitet: `system:serviceaccount:NAMESPACE:cvebridge-reporter`.
- PVC 1 GiB på klustrets standardlagring.

Om något avviker: kopiera bara de berörda raderna från `.env.advanced.example`
till `.env`. Till exempel `STACKROX_URL`, `STACKROX_SCANNER_COMPONENT`,
`STORAGE_CLASS`, `IMAGE_TAG`, en snävare `MATTERMOST_SCHEDULE_SCOPES` eller särskilda
`MATTERMOST_SCHEDULE_MANAGERS`. Tidigare fullständig JSON-konfiguration fungerar också.

Vid privat CA: lägg **publik** PEM i projektets git-ignorerade `certs/` och lägg till
`STACKROX_CA_FILE=certs/central-ca.pem` eller `MATTERMOST_CA_FILE=certs/mattermost-ca.pem`.
Render-kommandot ser projektmappen; en absolut värdsökväg utanför den är inte monterad.
Värden läses som data, aldrig som shellkod. Företagsvärden byggs inte in i imagen.

## 3. Mattermost ställs in en gång

Integrationsansvarig skapar botkontot och bjuder in det till den privata kanalen.
Registrera en Custom Slash Command i teamets integrationsinställningar:

| Fält | Värde |
| --- | --- |
| Command Trigger Word | `cve` |
| Request URL | `WEBHOOK_PUBLIC_URL` plus `/slash/cve` |
| Request Method | `POST` |
| Autocomplete | Exempel: `scan [namespace]`, `schedule`, `status` |

Kopiera kommandots token till `.env`. Ett valfritt `/acs` behöver ett separat
registrerat kommando och `MATTERMOST_ACS_COMMAND_TOKEN` från den avancerade mallen.
Vanliga teammedlemmar behöver ingen adminroll för kommandon eller formulär.
Mattermost-servern måste nå botens HTTPS-route inklusive dialog-callbacks.
Boten måste nå Mattermost, Central och Kubernetes API. Tillåt dessa anslutningar
enligt företagets nätverks- och Mattermost-inställningar.

## 4. Bygg, pusha och generera

```sh
./cvebridge.sh build
./cvebridge.sh push
./cvebridge.sh render
./cvebridge.sh image
```

För Podman: sätt `export CONTAINER_ENGINE=podman` först.
`push` kontrollerar oc-inloggningen och namespacet, hämtar registry-routen,
loggar in via din oc-token på stdin och pushar samma image genom routen.
Deployment använder den interna registry-adressen. Ingen token läggs i kommandoradens
lösenordsargument eller i Deployment för själva image-pushen.

Om du inte får läsa registry-routen, eller använder en anpassad route, ange den
adress plattformsteamet ger dig i `REGISTRY_PUSH_HOST` i `.env`. Saknas route eller
behörighet stoppar pushen; skriptet aktiverar inte klusterinställningar automatiskt.
TLS-certifikatet för registry-routen måste vara betrott av Docker/Podman.

`render` skapar privata filer med rätt image:

- `deploy/generated/bootstrap.yaml`: engångsbehörigheter.
- `deploy/generated/deployment.yaml`: ServiceAccounts, Secret, ConfigMap, PVC,
  Deployment, Service och OpenShift Route.

Filerna är Kubernetes List i JSON-format, vilket är giltig YAML för `oc apply`.
`.env` och genererade filer är git-ignorerade. `deployment.yaml` innehåller tokens.

## 5. Godkänn bootstrap en gång och applicera Deployment

Plattformsteamet granskar och applicerar bootstrap-filen en gång:

```sh
oc apply -f deploy/generated/bootstrap.yaml
```

Den ger appkontot rätt att skapa SubjectAccessReview på klusternivå och ger
reporteridentiteten `list deployments` i de uttryckligen godkända
schemanamespacen. De mål-namespacen ska redan finnas. En namespace-admin kan inte
själv skapa klusterbehörigheten. Inga nya behörigheter ges till de mänskliga kontona.

Applicera sedan din installation:

```sh
oc project cvebridge
oc apply -f deploy/generated/deployment.yaml
oc rollout status deployment/cvebridge
oc get pods,pvc,svc,route
oc logs deployment/cvebridge -c bot --tail=50
```

Byt `cvebridge` om du valde annat namespace. Imagen ligger i samma projekt som
boten och använder OpenShifts vanliga image-pull-behörighet för projektets
servicekonton. Plattformsteamet behöver verifiera den om standardrollerna har ändrats.
En extern registry kan väljas med `APP_IMAGE` och vid behov `IMAGE_PULL_SECRET`.
`Pending` PVC kräver lagringskontroll; `ImagePullBackOff` kräver kontroll av image
eller pull-behörighet. Byt imageversion vid uppgraderingar; `IMAGE_TAG` kan sättas
uttryckligen, annars används Git-revision eller projektfilernas innehåll.

## 6. Kontrollera i Mattermost

```text
/cve help
/cve status
/cve scan team-a
/cve schedule
```

Skanning ska ge rätt namespace, en Åtgärd-rad och JSON-bilaga. Öppna schemaformuläret,
välj dagar, tider och namespaces och spara. Välj sedan Provkör sparat schema och
kontrollera körhistoriken. Testa även att ett otillåtet konto eller namespace nekas.
Ingen separat webbplats behövs. Vid kommandofel: kontrollera route/TLS, Mattermosts
serveråtkomst, slash-token och botloggen. `/healthz` är bara ett processtest.

[Red Hats registry-dokumentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
beskriver intern adress, projektets push-behörighet och repository-formatet.
[Exponera registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/securing-exposing-registry)
beskriver den externa routen.
