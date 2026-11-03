# CVEBridge · manuell OpenShift-installation

Go-boten visar CVE-rapporter, åtgärder och schemaformulär direkt i Mattermost.
Scheman och larmstatus sparas på er befintliga PVC.

**Alla YAML-filer finns redan i `deploy/`.** Du fyller i `.env`, kör Docker- och
`oc`-kommandona nedan och redigerar image/PVC i Deployment själv.

## 1. Skapa din lokala .env

Om `.env` saknas:

```sh
cp -n .env.example .env
chmod 600 .env
```

Öppna `.env` i din editor. Byt exempelvärdena mot företagets värden.
Använd `NYCKEL=värde` utan yttre citattecken. Har du en äldre `.env`, ta bort
yttre enkla citattecken runt JSON-raderna. JSON skrivs så här:

```dotenv
MATTERMOST_KUBE_USER_MAP={"h8k3m2p9r7t6v5x4z1a0b2c3d4":"anna"}
```

### Var varje värde hämtas

Logga in i labbet med `oc login` först. `DITT_NAMESPACE` är projektet där både
boten och den färdiga PVC:n ska finnas.

| Fält | Så hämtar du det | Exempel |
| --- | --- | --- |
| `NAMESPACE` | Välj projekt med `oc project PROJEKTNAMN`. Kör `oc project -q` och kopiera namnet. | `security-tools` |
| `STATE_EXISTING_PVC` | Kör `oc get pvc -n DITT_NAMESPACE`. Kopiera **NAME** för den färdiga PVC:n. | `cvebridge-state` |
| `SCAN_NAMESPACES` | Kör `oc get projects`. Ange apparnas projektnamn, separerade med kommatecken. | `team-a,team-b` |
| `MATTERMOST_INTERNAL_URL` | Ta serverdelen av er Mattermost-länk, före `/teamnamn/channels/...`. Boten måste nå den. | `https://mattermost.foretagsnamn.se` |
| `MATTERMOST_BOT_TOKEN` | Mattermost-admin: **Integrations → Bot Accounts → Add Bot Account → Member → Create**. Kopiera **Access Token**, och bjud in boten till kanalen. | Den skapade Access Token-strängen. |
| `MATTERMOST_COMMAND_TOKEN` | **Integrations → Slash Commands → Add Slash Command**. Trigger `cve`, metod `POST`, Request URL enligt nedan. Klicka **Save** och kopiera **Token**. | Slash-kommandots token. |
| `MATTERMOST_CHANNEL_ID` | Öppna den privata rapportkanalen → **Visa info / View Info (i)** → kopiera **ID** längst ner. | Kanalens 26 tecken långa ID. |
| `MATTERMOST_KUBE_USER_MAP` | Mattermost-admin: **System Console → User Management → Users → personen → ID**. Samma person kör `oc whoami` i OpenShift. Skriv paret som JSON enligt exemplet ovan. | Mattermost-ID → samma persons OpenShift-användarnamn. |
| `STACKROX_URL` | Ta ACS Central-serverns adress från er ACS-inloggningslänk, utan sidans sökväg, eller be ACS-ansvarig om API-adressen. | `https://central.apps.ert-kluster.se` |
| `STACKROX_CLUSTER_ID` | Be ACS-ansvarig läsa `GET /v1/clusters`: välj posten där **name** är labbklustret och kopiera **id**. | ACS-kluster-ID, inte projektnamn. |
| `STACKROX_TOKEN` | ACS: **Platform Configuration → Integrations → Authentication Tokens → API Token → Generate Token**. Välj botens godkända roll → **Generate** → kopiera tokenen. | ACS API-tokenen. |
| `DATABASE_MONITOR_CHANNEL_ID` (valfritt) | Öppna privat driftkanal → **Visa info (i) → ID**. Bjud in boten. Samma rapportkanal kan användas. | Driftkanalens ID. |

**Användarmappningen:** lägg till ett par per mänsklig medlem i rapportkanalen.
Använd personens eget OpenShift-konto. Det ger inga nya klusterbehörigheter.

**ACS-rollen:** Read på Deployment, Image, Cluster, Namespace och Administration;
Write på Image. ACS-ansvarig godkänner rollen och access scope för er installation.
Botens token och ACS-token visas vid skapandet; spara dem direkt i din lokala fil.

**Mattermost Request URL** för `/cve`:

```text
http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve
```

Mattermost-servern måste nå tjänsten. Saknas integrationernas menyer behöver
Mattermost-admin hjälpa till. [Fler steg och exempel för .env](docs/ENV_VARDEN.md).
Interna adresser som `central.stackrox.svc` fungerar inom det kluster där tjänsten
finns. Central i ett annat kluster behöver en nåbar HTTPS-adress.

## 2. Bygg, tagga och pusha imagen själv

Kör kommandona ett i taget i samma terminal. Byt `DITT_NAMESPACE`.

```sh
oc login
oc project DITT_NAMESPACE

CVE_NAMESPACE=$(oc project -q)
CVE_TAG=$(date +%Y%m%d-%H%M%S)
CVE_REGISTRY=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')

docker build -t cvebridge:local .
oc whoami -t | docker login "$CVE_REGISTRY" --username cvebridge --password-stdin
docker tag cvebridge:local "$CVE_REGISTRY/$CVE_NAMESPACE/cvebridge:$CVE_TAG"
docker push "$CVE_REGISTRY/$CVE_NAMESPACE/cvebridge:$CVE_TAG"

printf '%s\n' "image-registry.openshift-image-registry.svc:5000/$CVE_NAMESPACE/cvebridge:$CVE_TAG"
```

Sista raden visar imageadressen som Deployment ska använda.
Taggen blir dagens datum och klockslag. Imagen innehåller ingen `.env`.

Från datorn använder pushen registryts nåbara route. Om du inte får läsa routen
ber du plattformsteamet om dess värdnamn och sätter `CVE_REGISTRY=VÄRDNAMNET`.
Om byggdatorn redan når klustrets interna DNS kan du i stället sätta:

```sh
CVE_REGISTRY=image-registry.openshift-image-registry.svc:5000
```

Docker behöver lita på registryts certifikat. Ditt konto behöver rätt att pusha
till valt projekt. Deployment använder alltid den interna adressen ovan.

## 3. Redigera de färdiga YAML-filerna

I `deploy/app/deployment.yaml` ändrar du två rader:

```yaml
image: image-registry.openshift-image-registry.svc:5000/CHANGE_ME_NAMESPACE/cvebridge:CHANGE_ME_TAG
# Längst ner under persistentVolumeClaim:
claimName: CHANGE_ME_PVC
```

Klistra in hela imageadressen från steg 2. Ange samma PVC-namn som i `.env`.

I `deploy/bootstrap.yaml` byter plattformsteamet:

- `CHANGE_ME_NAMESPACE` → botens namespace, samma som `NAMESPACE`.
- `CHANGE_ME_SCAN_NAMESPACE` → ett app-namespace från `SCAN_NAMESPACES`.

För flera app-namespaces kopieras filens **Role + RoleBinding** en gång per
app-namespace. Roller och namespace-listan i `.env` ska omfatta samma projekt.
Plattformsteamet applicerar därefter:

```sh
oc apply -f deploy/bootstrap.yaml
```

## 4. Läs in .env och applicera appen

Välj samma projekt som i `.env`. Secret-filen är ett tomt skelett; själva värdena
läses från `.env` med det manuella `oc`-kommandot nedan.

```sh
oc project DITT_NAMESPACE
oc apply -f deploy/app/secret.yaml

oc create secret generic cvebridge-integration --from-env-file=.env --dry-run=client -o yaml | oc apply --server-side --field-manager=cvebridge-env -f -

oc apply -f deploy/app/
oc rollout status deployment/cvebridge
```

`--server-side --field-manager=cvebridge-env` gör att din inlästa konfiguration
behålls när du applicerar YAML-skelettet igen. `.env` läses av `oc` och skickas
som en Secret; Kubernetes läser inte filen automatiskt från din dator.

| Fil som redan finns | Innehåll |
| --- | --- |
| `deploy/bootstrap.yaml` | Botens behörighetskontroll och reporterns godkända namespaces. |
| `deploy/app/deployment.yaml` | En botreplika, image, PVC och hälsokontroller. |
| `deploy/app/service.yaml` | Intern Service för Mattermost-kommandon. |
| `deploy/app/configmap.yaml` | Standardinställningar för boten. |
| `deploy/app/secret.yaml` | Secret-skelett som fylls från din lokala `.env`. |
| `deploy/app/serviceaccounts.yaml` | Botens och reporterns servicekonton. |
| `deploy/optional/route.yaml` | Valfri extern callback-route, se installationsguiden. |

De färdiga filerna använder `oc project` för appens namespace. PVC:n måste finnas
där och vara skrivbar för botens pod. Boten monterar den som `/data`.

## 5. Kontrollera i Mattermost

```text
/cve status
/cve scan team-a
/cve schedule
```

Byt `team-a` mot ett godkänt app-namespace. Vid fel:

```sh
oc get pods,pvc,svc
oc logs deployment/cvebridge -c bot --tail=50
```

Vid ändrad `.env` kör du Secret-kommandot i steg 4 igen och sedan:

```sh
oc rollout restart deployment/cvebridge
oc rollout status deployment/cvebridge
```

[Installation och TLS](docs/INSTALLATION.md) · [Driftbevakning](docs/DRIFTBEVAKNING.md) · [Skärmbilder](docs/BILDER.md)

YAML-filerna kan läggas i företagets interna Git. `.env` med tokenvärden hålls
lokal och är git-ignorerad. Använd företagets interna Git som mål för projektkoden.

Källor: [Mattermost botkonton](https://docs.mattermost.com/developers/integrate/reference/bot-accounts),
[slash-kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom),
[användar-ID](https://docs.mattermost.com/administration-guide/configure/user-management-configuration-settings#identify-a-users-id),
[kanal-ID](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/components/channel_info_rhs/about_area_channel.tsx),
[ACS API-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token),
[ACS klusterlista](https://github.com/stackrox/stackrox/blob/master/proto/api/v1/cluster_service.proto),
[OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry),
[oc/kubectl Secret från env-fil](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_secret_generic/).
