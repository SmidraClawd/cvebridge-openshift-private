# Starta Go-boten i OpenShift med få fält

## 1. Logga in och välj installationsnamespace

```sh
oc login
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

Öppna `.env` och byt `CHANGE_ME`. Mallen har korta grupper för OpenShift,
Mattermost och ACS. [Fälthjälpen](docs/ENV_VARDEN.md) visar var värdena hämtas.

Har ni redan en färdig PVC? Ange dess namn i `STATE_EXISTING_PVC` och använd
samma `NAMESPACE` som PVC:n. Deployment monterar den på `/data`; inga nya
lagringsresurser eller lagrings-Secrets skapas. Serveradress och lagringslösenord
behöver inte anges. Se [lagringsguiden](docs/NATVERKSLAGRING.md).

Serviceadresserna följer formen `service.namespace.svc:port`:

- Mattermost: `http://mattermost.mattermost.svc:8065` (anpassa till er Service).
- ACS Central: `STACKROX_URL`. `https://central.stackrox.svc:443` gäller i samma kluster.
- Bot: `http://cvebridge-webhook.NAMESPACE.svc:8001` (räknas ut automatiskt).
- Image: `image-registry.openshift-image-registry.svc:5000/NAMESPACE/cvebridge:TAGG`.

Sensorn skickar labbets klusterdata till ACS Central. Boten anropar Central för
skanningar och fynd; labbets Kubernetes-API används för behörighetskontroll.
Central kan stå i ett annat kluster. [Fälthjälpen](docs/ENV_VARDEN.md) visar hur
du läser ut adressen som den befintliga sensorn använder.

Standardinstallationen skapar en intern Service och ingen OpenShift Route.
Mattermost-servern måste nå klustrets interna DNS och botens Service. Om den
blockerar interna integrationer behöver admin godkänna botens servicevärd i
`AllowedUntrustedInternalConnections`. Inga breda undantag behövs.

De fyra ACS-token behåller separata behörigheter. Alla människor i kanalen behöver
sin riktiga kontomappning och redan godkänd rätt att lista deployments i valda
namespaces. Scheman använder samma kanal och namespace-lista. Bot-ID, image-tagg,
formuläradress och reporteridentitet räknas ut automatiskt.

Valfria inställningar finns i `.env.advanced.example`. Vid privat CA: lägg publik
PEM i `certs/` och ange exempelvis `STACKROX_CA_FILE=certs/central-ca.pem`.
Företagsvärden byggs inte in i imagen.

## 3. Mattermost ställs in en gång

Integrationsansvarig skapar botkontot och bjuder in det till den privata kanalen.
Registrera en Custom Slash Command i teamets integrationsinställningar:

| Fält | Värde |
| --- | --- |
| Command Trigger Word | `cve` |
| Request URL | `http://cvebridge-webhook.NAMESPACE.svc:8001/slash/cve` (byt NAMESPACE) |
| Request Method | `POST` |
| Autocomplete | Exempel: `scan [namespace]`, `schedule`, `status` |

Kopiera kommandots token till `.env`. Ett valfritt `/acs` behöver ett separat
registrerat kommando och `MATTERMOST_ACS_COMMAND_TOKEN` från den avancerade mallen.
Vanliga teammedlemmar behöver ingen adminroll för kommandon eller formulär.
Mattermost-servern måste nå botens interna Service inklusive dialog-callbacks.
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
Om byggmiljön når registryts interna DNS kan du i stället ange
`REGISTRY_PUSH_HOST=image-registry.openshift-image-registry.svc:5000`.
Deployment behåller alltid den interna imageadressen i standardflödet.

`render` skapar privata filer med rätt image:

- `deploy/generated/bootstrap.yaml`: engångsbehörigheter och eventuell nätverks-PV.
- `deploy/generated/deployment.yaml`: ServiceAccounts, Secret, ConfigMap, eventuell PVC,
  Deployment och intern Service.

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
Med `STATE_EXISTING_PVC` innehåller bootstrap inga lagringsresurser. PVC:n och
serveranslutningen hanteras av plattformen.

Applicera sedan din installation:

```sh
oc project cvebridge
oc apply -f deploy/generated/deployment.yaml
oc rollout status deployment/cvebridge
oc get pods,pvc,svc
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
Ingen separat webbplats behövs. Vid kommandofel: kontrollera serviceadress/port, Mattermosts
serveråtkomst, slash-token och botloggen. `/healthz` är bara ett processtest.

[Red Hats registry-dokumentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry)
beskriver intern adress, projektets push-behörighet och repository-formatet.
[Exponera registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/securing-exposing-registry)
beskriver den externa routen.
