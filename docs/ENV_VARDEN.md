# Fyll i .env: exempel och var du hämtar värdena

Kör `./cvebridge.sh init` i projektmappen och öppna `.env` i din editor.
Du fyller fortfarande bara i **12 företagsvärden**. `NAMESPACE=cvebridge` är förvalt.
Alla adresser, ID:n och konton i exemplen är påhittade och måste ersättas.
`CHANGE_ME_...` betyder att du ska klistra in ett riktigt värde lokalt.
Skicka inte tokens i chatten och committa inte din ifyllda `.env`.

## Så kan din fil se ut

```dotenv
NAMESPACE=cvebridge
WEBHOOK_PUBLIC_URL=https://cvebridge-webhook-cvebridge.apps.lab.foretag.example
MATTERMOST_INTERNAL_URL=https://mattermost.foretag.example
MATTERMOST_BOT_TOKEN=CHANGE_ME_BOT_ACCESS_TOKEN
MATTERMOST_COMMAND_TOKEN=CHANGE_ME_SLASH_COMMAND_TOKEN
MATTERMOST_CHANNEL_ID=a1b2c3d4e5f6g7h8i9j0k1l2m3
SCAN_NAMESPACES=team-a,team-b
MATTERMOST_KUBE_USER_MAP='{"n4o5p6q7r8s9t0u1v2w3x4y5z6":"anna@foretag.example"}'
STACKROX_CLUSTER_ID=5c5b7b22-6f42-4da9-b58f-5eb3d90a2f76
STACKROX_TOKEN=CHANGE_ME_ACS_READ_TOKEN
STACKROX_SCAN_TOKEN=CHANGE_ME_ACS_SCAN_TOKEN
STACKROX_STATUS_TOKEN=CHANGE_ME_ACS_STATUS_TOKEN
STACKROX_SCHEDULE_TOKEN=CHANGE_ME_ACS_SCHEDULE_TOKEN
```

JSON-värdet ska ligga på en rad. Behåll de enkla citattecknen runt JSON och de
dubbla citattecknen runt nycklar och värden. Skriv faktiska adresser och ID:n;
`.env` expanderar inte shellvariabler som `$NAMESPACE`.

## 1. OpenShift-projekt och botens adress

| Fält | Exempel | Så får du värdet |
| --- | --- | --- |
| `NAMESPACE` | `cvebridge` | Projektet där boten ska köras. `oc project -q` visar ditt valda projekt. Behåll förvalet om det är ert godkända installationsprojekt. |
| `WEBHOOK_PUBLIC_URL` | `https://cvebridge-webhook-cvebridge.apps.lab.foretag.example` | Botens planerade route. Hämta klustrets ingressdomän nedan eller be plattformsteamet om den godkända adressen. |
| `SCAN_NAMESPACES` | `team-a,team-b` | De exakta projekt som innehåller era workloads och som får skannas. Få listan godkänd av respektive projektägare. |

Efter din vanliga `oc login`:

```sh
oc project -q
oc get ingresses.config/cluster -o jsonpath='{.spec.domain}{"\n"}'
oc auth can-i list deployments.apps -n team-a
oc auth can-i list deployments.apps -n team-b
```

Om domänen är `apps.lab.foretag.example` kan en godkänd route vara
`cvebridge-webhook-cvebridge.apps.lab.foretag.example`. Ange hela adressen med
`https://` i `WEBHOOK_PUBLIC_URL`. Plattformsteamet behöver bekräfta DNS, TLS och
att Mattermost-servern kan nå den. Om kommandot ger `Forbidden` får du domänen
från plattformsteamet; botanvändning kräver ingen extra rätt att läsa ingresskonfiguration.

Vid första installationen planerar du adressen innan routen finns. `render` använder
adressen i manifestet och `oc apply` skapar routen. Efter installationen kontrollerar du:

```sh
oc -n cvebridge get route cvebridge-webhook -o jsonpath='{.spec.host}{"\n"}'
```

`WEBHOOK_PUBLIC_URL` tar emot Mattermost-kommandon och formulärsvar.
Imagen använder automatiskt
`image-registry.openshift-image-registry.svc:5000/cvebridge/cvebridge:TAGG`.
Registryts externa push-route hämtas av `./cvebridge.sh push`; den fyller du inte i
som webhook-adress. Boten kan installeras i `cvebridge` och skanna `team-a,team-b`.
Ett `yes` från `oc auth can-i` gäller ditt eget inloggade konto; övriga personer
och reporteridentiteten behöver också de rättigheter som installationsguiden beskriver.

[Red Hats dokumentation om routes och ingressdomän](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/ingress_and_load_balancing/routes)
beskriver hur domänen hämtas.

## 2. Mattermost: adress, bot och slash-kommando

`MATTERMOST_INTERNAL_URL` är Mattermosts basadress som boten kan nå.
Om webbläsaren visar `https://mattermost.foretag.example/devsecops/channels/team-security`
blir basadressen normalt `https://mattermost.foretag.example`. Be Mattermost-ansvarig
bekräfta adressen om servern nås via en annan intern adress från klustret.

Mattermost-admin gör botkontot en gång:

1. Öppna **Integrations → Bot Accounts → Add Bot Account**.
2. Skapa exempelvis `cvebridge` med rollen **Member**.
3. Kopiera den genererade **Access Token** till `MATTERMOST_BOT_TOKEN`.
   Kopiera själva hemligheten, inte dess Token ID. Token visas vid skapandet.
4. Lägg till boten i teamet och den godkända privata kanalen.

Om botkonton är avstängda aktiverar admin skapandet i
**System Console → Integrations → Bot Accounts** enligt er integrationspolicy.
Du fyller inte i botens användar-ID; det kontrolleras automatiskt via token.
[Mattermosts botguide](https://developers.mattermost.com/integrate/reference/bot-accounts/)
beskriver skapande och kanalmedlemskap.

Den som har rätt att hantera teamets integrationer skapar sedan kommandot:

1. Öppna **Integrations → Slash Commands → Add Slash Command**.
2. Ange trigger **`cve`**, metod **POST** och Request URL som din botadress plus
   `/slash/cve`. Med exemplet ovan blir det
   `https://cvebridge-webhook-cvebridge.apps.lab.foretag.example/slash/cve`.
3. Spara och kopiera kommandots **Token** till `MATTERMOST_COMMAND_TOKEN`.

Botens token och slash-kommandots token har olika uppgifter och ska ha varsitt
värde. Vanliga användare kör sedan `/cve` och schemaformuläret inne i Mattermost.
[Mattermosts guide för custom slash commands](https://developers.mattermost.com/integrate/slash-commands/custom/)
beskriver inställningarna. Ingen separat webbapp behövs för användarna.

## 3. Mattermost-ID:n och OpenShift-konton

`MATTERMOST_CHANNEL_ID` är kanalens stabila ID med 26 tecken.
Be Mattermost-ansvarig köra följande med sin redan konfigurerade `mmctl`:

```sh
mmctl channel search --team devsecops team-security
```

Byt `devsecops` och `team-security` mot teamets och kanalens namn i er Mattermost-URL.
Kopiera **channel ID** ur resultatet till `.env`.
[Mattermosts mmctl-guide](https://docs.mattermost.com/manage/mmctl-command-line-tool)
beskriver kanaluppslagningen. Du behöver inte installera eller autentisera mmctl
om ansvarig redan kan lämna kanal-ID:t.

För `MATTERMOST_KUBE_USER_MAP` behövs ett par per människa i kanalen:

| Del | Varifrån |
| --- | --- |
| JSON-nyckel, exempelvis `n4o5p6q7r8s9t0u1v2w3x4y5z6` | Mattermost-admin öppnar **System Console → User Management → Users**, väljer rätt person och kopierar **User ID**. |
| JSON-värde, exempelvis `anna@foretag.example` | Samma person loggar in i OpenShift och kör `oc whoami`. Använd exakt svaret, även om det skiljer sig från personens e-postadress. |

Exempel med två personer, båda med påhittade ID:n:

```dotenv
MATTERMOST_KUBE_USER_MAP='{"n4o5p6q7r8s9t0u1v2w3x4y5z6":"anna@foretag.example","b2c3d4e5f6g7h8i9j0k1l2m3n4":"erik@foretag.example"}'
```

Lägg till alla människor i kanalen, inte botkontot. Mappen kopplar identiteter;
den ger inte användarna nya OpenShift-rättigheter. Byt eller ta bort poster när
medlemskap ändras. [Mattermosts användaradministration](https://docs.mattermost.com/administration-guide/configure/user-management-configuration-settings)
beskriver var User ID finns.

## 4. ACS-kluster och fyra separata tokens

`STACKROX_CLUSTER_ID` är ID:t för det secured cluster som ACS visar.
Be ACS-ansvarig läsa **`GET /v1/clusters`** i Centrals API och lämna `id` för rätt
`name`. Exempel på de två relevanta fälten i svaret:

```json
{
  "clusters": [
    {"name": "openshift-lab", "id": "5c5b7b22-6f42-4da9-b58f-5eb3d90a2f76"}
  ]
}
```

Använd `id` som ACS returnerar. Klustrets visningsnamn, API-adress och OpenShifts
eget installations-ID ersätter inte detta värde. Anropet kräver ACS-läsbehörighet.
Central har en API-referens under `/api/docs`; där kan ACS-ansvarig kontrollera
ClusterService för sin installerade version.

ACS-ansvarig skapar eller återanvänder godkända roller och gör sedan följande för
**var och en** av de fyra tokenraderna:

1. Öppna **Platform Configuration → Integrations** i ACS Central.
2. Under **Authentication Tokens**, öppna **API Token → Generate Token**.
3. Ange ett namn från tabellen och välj en roll med rätt permission set och access scope.
4. Generera token och kopiera den direkt till motsvarande rad i din lokala `.env`.
   Den fullständiga token visas vid skapandet och kan inte hämtas igen efteråt.

| Rad i .env | Namnförslag | Behörighetsunderlag för den som skapar rollen |
| --- | --- | --- |
| `STACKROX_TOKEN` | `cvebridge-read` | Read för Deployment, Image, Cluster och Namespace i botens godkända inventeringsomfattning. |
| `STACKROX_SCAN_TOKEN` | `cvebridge-scan` | Read/Write för Image, för manuellt begärda imageskanningar. Begränsa omfattningen där ACS stöder det. |
| `STACKROX_STATUS_TOKEN` | `cvebridge-status` | Read för Administration, som används för CVE-databasens status. Detta är läsrätt till resursen, inte en Admin-roll. |
| `STACKROX_SCHEDULE_TOKEN` | `cvebridge-schedule` | Read för Deployment, Cluster och Namespace samt Read/Write för Image. Access scope ska omfatta endast godkända schemanamespaces i valt kluster. |

Tabellen motsvarar projektets uppdelning av API-anrop. ACS-ansvarig behöver
kontrollera resursernas scope-stöd och rättigheterna i er ACS-version. Håll fyra
separata tokenvärden även om ni redan har andra integrationskonton.
[Red Hats guide om API-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token)
beskriver hur token skapas med vald roll.

Central-adressen är förvald till `https://central.stackrox.svc:443`. Be ACS-ansvarig
bekräfta service och namespace. Bara om er adress avviker lägger du till exempelvis
`STACKROX_URL=https://central.acs.foretag.example` från `.env.advanced.example`.
Behöver ni en privat CA får du dess **publika CA-certifikat** från ansvarig,
lägger det i `certs/central-ca.pem` och sätter `STACKROX_CA_FILE=certs/central-ca.pem`.
Certifikatet ska vara PEM och CA:n ska verifiera serverns certifikat.

## 5. När värdena är ifyllda

```sh
./cvebridge.sh build
./cvebridge.sh push
./cvebridge.sh render
```

Fortsätt sedan med bootstrap och Deployment i [START_HAR.md](../START_HAR.md#5-godkänn-bootstrap-en-gång-och-applicera-deployment).
Behåll din ifyllda `.env` och `deploy/generated/deployment.yaml` lokalt; den senare
innehåller Kubernetes Secret med dina tokens. Själva imagen innehåller koden.
Efter installationen provar du `/cve status`, `/cve scan team-a` och `/cve schedule`
i den godkända Mattermost-kanalen.
