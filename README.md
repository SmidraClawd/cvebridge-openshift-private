# CVEBridge · ConfigMap och Secret i OpenShift

Go-boten visar CVE-rapporter, åtgärder och schemaformulär direkt i Mattermost.
Scheman och larmstatus sparas på er befintliga PVC.

**Ingen `.env` behövs.** Du fyller konfiguration i ConfigMap och tokenvärden i
Secret, bygger imagen lokalt och applicerar de färdiga YAML-filerna med `oc`.
Klustrets betrodda CA-paket monteras automatiskt i boten via en separat ConfigMap.
Imagen innehåller inget eget CA-paket.

## 1. Fyll i ConfigMap och Secret

Öppna **`deploy/app/configmap.yaml`** och fyll i adresser, kanal-ID,
användarmappning och app-namespaces. Standardinställningarna längst ner kan
normalt behållas. Alla värden under `data` ska vara YAML-strängar.

Skapa din lokala Secret-fil en gång och fyll de tre tokenvärdena:

```sh
cp -n deploy/app/secret.yaml.example deploy/app/secret.yaml
chmod 600 deploy/app/secret.yaml
```

Öppna **`deploy/app/secret.yaml`** och ersätt de tre `CHANGE_ME`-värdena.
Du skriver vanliga tokensträngar under `stringData`; ingen base64-kodning behövs.
Den ifyllda filen är git-ignorerad. Mallen innehåller bara platshållare.

### Var varje värde hämtas

Logga in i labbet med `oc login`. `DITT_NAMESPACE` är projektet där boten och
PVC:n ska finnas. Namespace och PVC anges i kommandon/YAML, inte i ConfigMap.

| Värde | Var du fyller i det | Så hämtar du värdet |
| --- | --- | --- |
| Botens namespace | `oc project` och `deploy/bootstrap.yaml` | Välj med `oc project PROJEKTNAMN`. `oc project -q` visar valt namn. |
| PVC-namn | `claimName` i `deploy/app/deployment.yaml` | `oc get pvc -n DITT_NAMESPACE` → kopiera rätt **NAME**. |
| `SCAN_NAMESPACES` | ConfigMap | `oc get projects` → välj apparnas projektnamn, exempelvis `team-a,team-b`. |
| `MATTERMOST_INTERNAL_URL` | ConfigMap | Er vanliga HTTPS-serveradress, före `/teamnamn/channels/...`, exempelvis `https://mattermost.foretaget.se`. Boten lägger själv till `/api/v4`. INTERNAL är ett äldre namn; adressen får vara extern. |
| `MATTERMOST_CHANNEL_ID` | ConfigMap | Privat rapportkanal → **Visa info / View Info (i)** → kopiera **ID** längst ner. Det är 26 tecken. |
| `MATTERMOST_KUBE_USER_MAP` | ConfigMap | Mattermost-admin: **System Console → User Management → Users → personen → ID**. Samma person kör `oc whoami`. Koppla värdena som JSON enligt nedan. |
| `STACKROX_URL` | ConfigMap | ACS Central-serverns vanliga HTTPS-adress från er ACS-inloggningslänk, utan sidans sökväg. Boten lägger själv till `/v1`. |
| `STACKROX_CLUSTER_ID` | ConfigMap | ACS-ansvarig läser `GET /v1/clusters`, matchar labbklustrets **name** och kopierar dess **id**. |
| `MATTERMOST_DIALOG_URL` | ConfigMap | Botens egen route: `https://ERT_BOT_VARDNAMN/slash/cve/dialog`. Använd samma värdnamn som i `deploy/optional/route.yaml`. |
| `DATABASE_MONITOR_CHANNEL_ID` (valfritt) | ConfigMap | Privat driftkanal → **Visa info (i) → ID**. Bjud in boten där. Rapportkanalens ID kan användas om ni vill samla meddelandena. |
| `MATTERMOST_BOT_TOKEN` | Secret | Mattermost-admin: **Integrations → Bot Accounts → Add Bot Account**, välj **Member**, skapa och kopiera **Access Token**. Bjud in boten till kanalen. |
| `MATTERMOST_COMMAND_TOKEN` | Secret | **Integrations → Slash Commands → Add Slash Command**. Trigger `cve`, metod `POST`, Request URL enligt nedan. **Save** → kopiera **Token**. |
| `STACKROX_TOKEN` | Secret | ACS: **Platform Configuration → Integrations → Authentication Tokens → API Token → Generate Token**. Välj godkänd roll → **Generate** → kopiera tokenen. |

Exempel på användarmappning i ConfigMap, om Annas `oc whoami` visar `anna`:

```yaml
MATTERMOST_KUBE_USER_MAP: '{"h8k3m2p9r7t6v5x4z1a0b2c3d4":"anna"}'
```

Lägg till ett par per mänsklig medlem i rapportkanalen. Mappningen kopplar
samma person mellan systemen och ger inga nya klusterbehörigheter.

ACS-rollen behöver **Read** på Deployment, Image, Cluster, Namespace och
Administration samt **Write** på Image. ACS-ansvarig godkänner roll och access scope.
Botens och ACS-tokenen visas vid skapandet, så kopiera dem direkt till Secret-filen.

### Mattermost måste också nå boten

Boten anropar Mattermost och ACS via HTTPS-adresserna i ConfigMap.
Mattermost-servern anropar i sin tur boten när du använder `/cve` och formulär.

När Mattermost ligger utanför klustret fyller du värdnamnet i
`deploy/optional/route.yaml`. Ange samma värdnamn i `MATTERMOST_DIALOG_URL` och
registrera `/cve` med **Request URL**:

```text
https://ERT_BOT_VARDNAMN/slash/cve
```

[Route-stegen](docs/INSTALLATION.md#om-mattermost-behöver-en-extern-route) visar inställningarna.
Om Mattermost-servern redan når klustrets Service kan callback i ConfigMap vara
`http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve/dialog` och Request URL
samma adress med `/slash/cve` som sökväg. Byt `DITT_NAMESPACE` i hela adressen.

Boten får automatiskt botens namespace och åtkomst till Kubernetes interna API
via sitt ServiceAccount. [Fler konfigurationsexempel](docs/KONFIGURATION.md).

### Företagets certifikat

`deploy/app/trusted-ca.yaml` ber OpenShift fylla **`cvebridge-trusted-ca`** med
klustrets betrodda CA-paket. Deployment monterar filen på `/ca/ca-bundle.crt`;
`MATTERMOST_CA_FILE` och `STACKROX_CA_FILE` är redan inställda på den sökvägen.
Du behöver inte exportera certifikat eller bygga in dem i imagen.
Boten litar enbart på CA-certifikaten i respektive angiven fil. Vilka CA som
ingår i klustrets paket styrs av plattformsteamets konfiguration; paketet kan
innehålla både vanliga och företagets egna CA-certifikat.

Det fungerar för era egna certifikat om deras utfärdande CA finns med i paketet.
Kluster-API:t kan använda en annan CA. Om boten får certifikatfel behöver
plattformsteamet bekräfta rätt CA för Mattermost och ACS.
[Kontroll och alternativ CA-fil](docs/INSTALLATION.md#klustrets-betrodda-ca-paket).

## 2. Bygg, tagga och pusha imagen själv

Kör kommandona ett i taget i samma Bash-terminal. Byt `DITT_NAMESPACE`.
Podman bygger projektets befintliga `Dockerfile`.

```sh
oc login
oc project DITT_NAMESPACE

CVE_NAMESPACE=$(oc project -q)
CVE_TAG=$(date +%Y%m%d-%H%M%S)
CVE_REGISTRY=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')

podman build -f Dockerfile -t localhost/cvebridge:local .
oc whoami -t | podman login "$CVE_REGISTRY" --username cvebridge --password-stdin
podman tag localhost/cvebridge:local "$CVE_REGISTRY/$CVE_NAMESPACE/cvebridge:$CVE_TAG"
podman push "$CVE_REGISTRY/$CVE_NAMESPACE/cvebridge:$CVE_TAG"

printf '%s\n' "image-registry.openshift-image-registry.svc:5000/$CVE_NAMESPACE/cvebridge:$CVE_TAG"
```

Sista raden visar imageadressen som Deployment ska använda.
Taggen blir dagens datum och klockslag. Företagets konfiguration och tokenvärden byggs inte in i imagen.

Från datorn använder pushen registryts nåbara route. Om du inte får läsa routen
ber du plattformsteamet om dess värdnamn och sätter `CVE_REGISTRY=VÄRDNAMNET`.
Om byggdatorn redan når klustrets interna DNS kan du i stället sätta:

```sh
CVE_REGISTRY=image-registry.openshift-image-registry.svc:5000
```

Podman behöver lita på registryts certifikat. Ditt konto behöver rätt att pusha
till valt projekt. Deployment använder alltid den interna adressen ovan.

## 3. Redigera Deployment och bootstrap

I `deploy/app/deployment.yaml` ändrar du image och PVC-namn:

```yaml
image: image-registry.openshift-image-registry.svc:5000/CHANGE_ME_NAMESPACE/cvebridge:CHANGE_ME_TAG
# Längst ner under persistentVolumeClaim:
claimName: CHANGE_ME_PVC
```

Klistra in hela imageadressen från steg 2. PVC:n ska finnas i botens namespace.

Plattformsteamet fyller i `deploy/bootstrap.yaml`:

- `CHANGE_ME_NAMESPACE` → botens namespace.
- `CHANGE_ME_SCAN_NAMESPACE` → ett app-namespace från ConfigMaps `SCAN_NAMESPACES`.

För flera app-namespaces kopieras filens **Role + RoleBinding** en gång per
app-namespace. Därefter applicerar plattformsteamet:

```sh
oc apply -f deploy/bootstrap.yaml
```

## 4. Applicera YAML och starta boten

Fyll ConfigMap, Secret och Deployment innan du kör kommandona. Välj rätt projekt:

```sh
oc project DITT_NAMESPACE
oc apply -f deploy/app/secret.yaml
oc apply -f deploy/app/
```

Om du använder botens route, applicera även den ifyllda filen:

```sh
oc apply -f deploy/optional/route.yaml
```

Kontrollera att boten startar:

```sh
oc rollout status deployment/cvebridge
oc logs deployment/cvebridge -c bot --tail=50
```

| Fil | Innehåll |
| --- | --- |
| `deploy/app/configmap.yaml` | Adresser, kanal-ID, användarmappning, app-namespaces och standardinställningar. |
| `deploy/app/trusted-ca.yaml` | Separat ConfigMap som OpenShift fyller med klustrets betrodda CA-paket. |
| `deploy/app/secret.yaml.example` | Mall för de tre tokenvärdena. Kopieras till lokal `secret.yaml`. |
| `deploy/app/deployment.yaml` | En botreplika, image, PVC och `envFrom` från ConfigMap och Secret. |
| `deploy/app/service.yaml` | Intern Service för botens inkommande anrop. |
| `deploy/app/serviceaccounts.yaml` | Botens och reporterns servicekonton. |
| `deploy/bootstrap.yaml` | Behörighetskontroll och reporterns godkända namespaces. |
| `deploy/optional/route.yaml` | Botens nåbara HTTPS-adress om Mattermost behöver en route. |

Kubernetes skickar ConfigMap och Secret som miljövariabler till botprocessen.
Du behöver ingen lokal miljöfil eller något hjälpskript.

**Uppdaterar du en äldre installation?** Den nya Deployment-filen använder
Secret **`cvebridge-tokens`**. Kopiera de tre befintliga tokenvärdena till den
nya Secret-filen. Tidigare import till `cvebridge-integration` påverkar då inte
värdena i din ConfigMap.

## 5. Kontrollera och uppdatera

Testa i rapportkanalen:

```text
/cve status
/cve scan team-a
/cve schedule
```

Byt `team-a` mot ett godkänt app-namespace. När du ändrar ConfigMap eller Secret:

```sh
oc apply -f deploy/app/configmap.yaml
oc apply -f deploy/app/secret.yaml
oc rollout restart deployment/cvebridge
oc rollout status deployment/cvebridge
```

Boten läser miljövariabler när processen startar. PVC:n bevarar scheman och larmstatus.
När CA-paketet förnyas kör du också `oc rollout restart deployment/cvebridge`;
boten läser certifikaten vid start. Imagen behöver inte byggas om för CA-byte.

**Uppdatering från en äldre image:** Bygg och pusha en ny image enligt steg 2,
byt tagg i Deployment och applicera filerna för att ta bort det tidigare
inbyggda standardpaketet. Efter det hanteras CA-byten genom montering och omstart.

[Installation och TLS](docs/INSTALLATION.md) · [Driftbevakning](docs/DRIFTBEVAKNING.md) · [Skärmbilder](docs/BILDER.md)

ConfigMap och de övriga mallarna kan sparas i företagets interna Git.
Den ifyllda Secret-filen hålls lokal och är git-ignorerad.

Källor: [Kubernetes ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/),
[Kubernetes Secret](https://kubernetes.io/docs/concepts/configuration/secret/),
[Mattermost botkonton](https://docs.mattermost.com/developers/integrate/reference/bot-accounts),
[slash-kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom),
[användar-ID](https://docs.mattermost.com/administration-guide/configure/user-management-configuration-settings#identify-a-users-id),
[kanal-ID](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/components/channel_info_rhs/about_area_channel.tsx),
[ACS API-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token),
[ACS klusterlista](https://github.com/stackrox/stackrox/blob/master/proto/api/v1/cluster_service.proto),
[OpenShift registry](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/registry/accessing-the-registry),
[OpenShift CA-injektion](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html-single/configuring_network_settings/configuring_network_settings#certificate-injection-using-operators),
[Podman build](https://docs.podman.io/en/latest/markdown/podman-build.1.html),
[Podman login](https://docs.podman.io/en/latest/markdown/podman-login.1.html).
