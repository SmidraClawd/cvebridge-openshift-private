# ConfigMap och Secret – så hittar du värdena

Konfiguration fylls i `deploy/app/configmap.yaml`. De tre tokenvärdena fylls i
en lokal `deploy/app/secret.yaml`, kopierad från `secret.yaml.example`.
Ingen `.env` behövs. Deployment läser värdena genom `envFrom`.
Exemplen visar formatet; ersätt dem med era värden.

## 1. OpenShift – kör efter oc login

```sh
oc project -q
oc get pvc -n DITT_NAMESPACE
oc get projects
```

Byt `DITT_NAMESPACE` mot projektet där boten och den färdiga PVC:n ska finnas.

| Fält | Så hämtar du värdet | Exempel |
| --- | --- | --- |
| Botens namespace | `oc project -q` visar valt projekt. Välj först botens projekt med `oc project PROJEKTNAMN`. | `security-tools` |
| PVC-namn (`claimName` i Deployment) | `oc get pvc -n DITT_NAMESPACE`. Kopiera **NAME** för er färdiga PVC. | `cvebridge-state` |
| `SCAN_NAMESPACES` | `oc get projects`. Välj projektnamnen där apparna som ska skannas finns. | `team-a,team-b` |

PVC-namnet är namnet i OpenShift. Nätverkssökvägen bakom PVC:n skrivs inte här.
Ange PVC-namnet som `claimName` i `deploy/app/deployment.yaml`.
Imageadress och tagg väljer du med de manuella Podman-kommandona i README och
klistrar in på Deployment-filens `image`-rad. Namespace väljs med `oc project`
och hämtas automatiskt av botprocessen.

**CA-certifikat:** `MATTERMOST_CA_FILE` och `STACKROX_CA_FILE` är förifyllda med
`/ca/ca-bundle.crt`. OpenShift levererar filen via den separata ConfigMapen
`cvebridge-trusted-ca`; du behöver inget ytterligare tokenvärde eller någon
certifikatexport. Plattformsteamet behöver bekräfta att företagets CA för
Mattermost och ACS ingår i klustrets betrodda paket.
Imagen innehåller inget eget CA-paket; varje HTTPS-klient litar bara på sin
angivna CA-fil. Ingen Kubernetes-API-klient eller ServiceAccount-token behövs i driftläget.
[Kontroll och CA-byte](INSTALLATION.md#klustrets-betrodda-ca-paket).

## 2. Mattermost – adresser och kanaler i ConfigMap

| Fält | Så hämtar du värdet | Exempel |
| --- | --- | --- |
| `MATTERMOST_INTERNAL_URL` | Ta er vanliga HTTPS-serveradress: allt före `/teamnamn/channels/...`. Trots variabelnamnet får adressen vara extern. Boten lägger till `/api/v4`. | `https://mattermost.foretagsnamn.se` |
| `MATTERMOST_CHANNEL_ID` | Öppna den privata rapportkanalen → **Visa info / View Info** via informationsikonen (i) → kopiera **ID** längst ner. | 26 tecken, exempelvis `h8k3m2p9r7t6v5x4z1a0b2c3d4` |
| `DATABASE_MONITOR_CHANNEL_ID` **(valfritt)** | Öppna den privata driftkanalen och hämta **ID** på samma sätt. Bjud in boten där. | Driftkanalens eget ID, eller samma ID som rapportkanalen. |

Kanallänken kan sluta med `team-security`, men det är kanalens namn.
I ID-fälten ska den 26 tecken långa strängen från **ID** stå.
I driftläget behöver inga medlemmar användarmappning eller egna OpenShift-konton.

`MATTERMOST_INTERNAL_URL` är ett äldre variabelnamn och kräver ingen `.svc`-adress.
Ange företagets nåbara HTTPS-adress. Lägg inte till `/api/v4` i värdet.

## 3. Mattermost – de två tokenvärdena

**`MATTERMOST_BOT_TOKEN` – botens Access Token**

1. Mattermost-admin öppnar **Integrations → Bot Accounts → Add Bot Account**.
2. Skapa boten med rollen **Member**.
3. Kopiera **Access Token** från bekräftelsesidan till Secret-fältet `MATTERMOST_BOT_TOKEN`.
4. Bjud in boten till rapportkanalen och eventuell driftkanal.

Det är Access Token du ska kopiera. Token ID är ett annat värde. Tokenen visas
vid skapandet; en befintlig borttappad token behöver ersättas med en ny.

**`MATTERMOST_COMMAND_TOKEN` – token för /cve**

1. Öppna **Integrations → Slash Commands → Add Slash Command**.
2. Ange **Command Trigger Word:** `cve` och **Request Method:** `POST`.
3. Ange **Request URL:** `https://ERT_BOT_VARDNAMN/slash/cve` när Mattermost når boten via route.
4. Klicka **Save** och kopiera **Token** till Secret-fältet `MATTERMOST_COMMAND_TOKEN`.

Byt `ERT_BOT_VARDNAMN` mot botens route. Sätt även ConfigMaps
`MATTERMOST_DIALOG_URL` till `https://ERT_BOT_VARDNAMN/slash/cve/dialog`.
Mattermost-servern måste nå adressen. Se [route-stegen](INSTALLATION.md#om-mattermost-behöver-en-extern-route).
Om servern redan når klustrets Service kan intern Request URL användas enligt README.
Om menyerna saknas ber du Mattermost-admin aktivera integrationerna eller skapa
boten/kommandot. Du behöver inte ge själva boten adminroll.

## 4. Driftkanalen ersätter användarmappningen

Skapa en privat kanal för driften, bjud in boten och driftkollegorna och ange
kanalens ID i `MATTERMOST_CHANNEL_ID`. `ACCESS_MODE: operations` är förifyllt.
Alla medlemmar kan köra status, skanningar och scheman för `SCAN_NAMESPACES`.
När en kollega tillkommer räcker det att bjuda in personen till kanalen.

`MATTERMOST_KUBE_USER_MAP` behövs inte. Boten frågar ACS direkt och gör inga
personliga behörighetskontroller mot OpenShift. Inga reporterroller eller
SubjectAccessReview-behörigheter behöver skapas.

## 5. ACS Central – adress och kluster-ID i ConfigMap, token i Secret

| Fält | Så hämtar du värdet | Exempel |
| --- | --- | --- |
| `STACKROX_URL` | Ta Central-serverns adress från er ACS-inloggningslänk, eller be ACS-ansvarig om den nåbara API-adressen. Ta bort sidans sökväg. | `https://central.apps.ert-kluster.se` |
| `STACKROX_CLUSTER_ID` | Be ACS-ansvarig om **id** för labbklustret i `GET /v1/clusters`. Matcha klustrets **name**. | Ett ACS-kluster-ID, inte OpenShifts projektnamn. |
| `STACKROX_TOKEN` | Skapa en API-token i ACS enligt stegen nedan. | Tokensträngen som visas efter Generate. |

Så skapar ACS-ansvarig tokenen:

1. Öppna **Platform Configuration → Integrations**.
2. Under **Authentication Tokens**, välj **API Token → Generate Token**.
3. Ange namn, exempelvis `cvebridge`, och den godkända rollen för boten.
4. Klicka **Generate** och kopiera tokenen till Secret-fältet `STACKROX_TOKEN`.

Rollen behöver **Read** på **Deployment, Image, Cluster, Namespace och
Administration**, samt **Write** på **Image** för skanningsbeställningar.
ACS-ansvarig kontrollerar roll och access scope för er version och avsedda kluster.
Tokenen kan inte visas igen efter att skapandet är stängt.

`STACKROX_URL` är Centrals nåbara HTTPS-serveradress, även när Central ligger
utanför labbklustret. Lägg inte till `/v1` i värdet. Sensorn rapporterar till
Central; boten frågar Centrals API. Endast om ni uttryckligen vill använda en
intern Service-adress till en Central i samma kluster kan en `.svc`-adress anges.

En gemensam ACS-token räcker. Separata token kan anges i Secret som uttryckliga
undantag. [Valfria YAML-fält](config-options.example.yaml) visar placeringen.

## 6. Skapa och applicera Secret

```sh
cp -n deploy/app/secret.yaml.example deploy/app/secret.yaml
chmod 600 deploy/app/secret.yaml
```

Fyll de tre `stringData`-värdena i din lokala Secret-fil. Ange vanliga
strängar; ingen base64-kodning behövs. Den ifyllda filen är git-ignorerad.

```sh
oc project DITT_NAMESPACE
oc apply -f deploy/app/secret.yaml
oc apply -f deploy/app/
```

ConfigMap kan sparas med företagets konfiguration i interna Git. Tokenvärden
ska bara finnas i den lokala Secret-filen och Kubernetes Secret.
Vid ändring: applicera filerna igen och kör `oc rollout restart deployment/cvebridge`.

Källor: [botkonton](https://docs.mattermost.com/developers/integrate/reference/bot-accounts),
[slash-kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom),
[kanal-ID i Mattermosts informationspanel](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/components/channel_info_rhs/about_area_channel.tsx),
[ACS API-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token),
[ACS klusterlista](https://github.com/stackrox/stackrox/blob/master/proto/api/v1/cluster_service.proto).
