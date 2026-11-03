# Fyll i .env – så hittar du värdena

Kopiera `.env.example` till `.env` med `cp -n .env.example .env` och öppna filen.
En befintlig `.env` behålls. `oc` läser sedan filen med `--from-env-file=.env`.
Fyll i de **11 grundfälten**. Driftbevakning är ett valfritt extra fält.
Exemplen visar formatet; du ersätter dem med företagets värden.

## 1. OpenShift – kör efter oc login

```sh
oc project -q
oc get pvc -n DITT_NAMESPACE
oc get projects
oc whoami
```

Byt `DITT_NAMESPACE` mot projektet där boten och den färdiga PVC:n ska finnas.

| Fält | Så hämtar du värdet | Exempel |
| --- | --- | --- |
| `NAMESPACE` | `oc project -q` visar valt projekt. Välj först botens projekt med `oc project PROJEKTNAMN`. | `security-tools` |
| `STATE_EXISTING_PVC` | `oc get pvc -n DITT_NAMESPACE`. Kopiera **NAME** för er färdiga PVC. | `cvebridge-state` |
| `SCAN_NAMESPACES` | `oc get projects`. Välj projektnamnen där apparna som ska skannas finns. | `team-a,team-b` |

PVC-namnet är namnet i OpenShift. Nätverkssökvägen bakom PVC:n skrivs inte här.
Kopiera också PVC-namnet till `claimName` i `deploy/app/deployment.yaml`.
Imageadress och tagg väljer du med de manuella Docker-kommandona i README och
klistrar in på Deployment-filens `image`-rad. `.env` ersätter inte YAML-text automatiskt.

## 2. Mattermost – adress och kanaler

| Fält | Så hämtar du värdet | Exempel |
| --- | --- | --- |
| `MATTERMOST_INTERNAL_URL` | Ta serverdelen av er Mattermost-länk: allt före `/teamnamn/channels/...`. Adressen ska vara nåbar från boten. | `https://mattermost.foretagsnamn.se` |
| `MATTERMOST_CHANNEL_ID` | Öppna den privata rapportkanalen → **Visa info / View Info** via informationsikonen (i) → kopiera **ID** längst ner. | 26 tecken, exempelvis `h8k3m2p9r7t6v5x4z1a0b2c3d4` |
| `DATABASE_MONITOR_CHANNEL_ID` **(valfritt)** | Öppna den privata driftkanalen och hämta **ID** på samma sätt. Bjud in boten där. | Driftkanalens eget ID, eller samma ID som rapportkanalen. |

Kanallänken kan sluta med `team-security`, men det är kanalens namn.
I ID-fälten ska den 26 tecken långa strängen från **ID** stå.
För enbart driftstatus behöver driftkanalens medlemmar ingen användarmappning.

`http://mattermost.mattermost.svc:8065` i mallen är ett internt exempel.
Använd det bara om tjänsten faktiskt heter så och boten når den i samma kluster.

## 3. Mattermost – de två tokenvärdena

**`MATTERMOST_BOT_TOKEN` – botens Access Token**

1. Mattermost-admin öppnar **Integrations → Bot Accounts → Add Bot Account**.
2. Skapa boten med rollen **Member**.
3. Kopiera **Access Token** från bekräftelsesidan till `.env`.
4. Bjud in boten till rapportkanalen och eventuell driftkanal.

Det är Access Token du ska kopiera. Token ID är ett annat värde. Tokenen visas
vid skapandet; en befintlig borttappad token behöver ersättas med en ny.

**`MATTERMOST_COMMAND_TOKEN` – token för /cve**

1. Öppna **Integrations → Slash Commands → Add Slash Command**.
2. Ange **Command Trigger Word:** `cve` och **Request Method:** `POST`.
3. Ange **Request URL:** `http://cvebridge-webhook.DITT_NAMESPACE.svc:8001/slash/cve`.
4. Klicka **Save** och kopiera **Token** till `.env`.

Byt `DITT_NAMESPACE`. Mattermost-servern måste nå adressen; se
[installationen](INSTALLATION.md) om intern anslutning blockeras eller en route behövs.
Om menyerna saknas ber du Mattermost-admin aktivera integrationerna eller skapa
boten/kommandot. Du behöver inte ge själva boten adminroll.

## 4. Koppla Mattermost-personen till OpenShift-personen

**`MATTERMOST_KUBE_USER_MAP`** fylls med en koppling per mänsklig medlem i
rapportkanalen:

1. Mattermost-admin: **System Console → User Management → Users → välj personen**.
   Kopiera personens **ID**.
2. Samma person kör `oc whoami` efter sin egen inloggning i OpenShift.
3. Lägg personens Mattermost-ID till vänster och OpenShift-användarnamn till höger.

Om Annas Mattermost-ID är `h8k3m2p9r7t6v5x4z1a0b2c3d4` och hennes `oc whoami`
visar `anna`, skriver du:

```dotenv
MATTERMOST_KUBE_USER_MAP={"h8k3m2p9r7t6v5x4z1a0b2c3d4":"anna"}
```

Fler personer läggs till som fler par i samma JSON-objekt. Koppla varje person
till sitt eget konto. Boten använder kopplingen för att kontrollera personens
befintliga namespace-behörigheter; den ger inte nya rättigheter.

## 5. ACS Central – adress, kluster-ID och token

| Fält | Så hämtar du värdet | Exempel |
| --- | --- | --- |
| `STACKROX_URL` | Ta Central-serverns adress från er ACS-inloggningslänk, eller be ACS-ansvarig om den nåbara API-adressen. Ta bort sidans sökväg. | `https://central.apps.ert-kluster.se` |
| `STACKROX_CLUSTER_ID` | Be ACS-ansvarig om **id** för labbklustret i `GET /v1/clusters`. Matcha klustrets **name**. | Ett ACS-kluster-ID, inte OpenShifts projektnamn. |
| `STACKROX_TOKEN` | Skapa en API-token i ACS enligt stegen nedan. | Tokensträngen som visas efter Generate. |

Så skapar ACS-ansvarig tokenen:

1. Öppna **Platform Configuration → Integrations**.
2. Under **Authentication Tokens**, välj **API Token → Generate Token**.
3. Ange namn, exempelvis `cvebridge`, och den godkända rollen för boten.
4. Klicka **Generate** och kopiera tokenen till `STACKROX_TOKEN`.

Rollen behöver **Read** på **Deployment, Image, Cluster, Namespace och
Administration**, samt **Write** på **Image** för skanningsbeställningar.
ACS-ansvarig kontrollerar roll och access scope för er version och avsedda kluster.
Tokenen kan inte visas igen efter att skapandet är stängt.

`https://central.stackrox.svc:443` i mallen fungerar bara om Central finns på den
interna adressen i samma kluster. När Central finns i ett annat kluster anger
du dess nåbara HTTPS-adress. Sensorn rapporterar till Central; boten frågar Central.

En gemensam ACS-token räcker i grundfilen. Har ni redan separata token kan de
behållas. Avancerade undantag finns i [env-options.example](env-options.example).

Fyll värdena lokalt i `.env`. Använd inte yttre citattecken runt värdena:
`oc --from-env-file` behåller sådana tecken bokstavligt, även runt JSON.
Skriv inga kommentarer på samma rad efter ett värde.

Importera med kommandot i README. Filens alla grundvärden hamnar i appens Secret.
Secret-skelettet i `deploy/app/secret.yaml` innehåller inga tokenvärden. Behåll
`.env` och eventuella utdrag med tokenvärden utanför företagets Git.

Källor: [botkonton](https://docs.mattermost.com/developers/integrate/reference/bot-accounts),
[slash-kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom),
[användar-ID](https://docs.mattermost.com/administration-guide/configure/user-management-configuration-settings#identify-a-users-id),
[kanal-ID i Mattermosts informationspanel](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/components/channel_info_rhs/about_area_channel.tsx),
[ACS API-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token),
[ACS klusterlista](https://github.com/stackrox/stackrox/blob/master/proto/api/v1/cluster_service.proto).
