# Fyll i .env

Kör `./cvebridge.sh init` och öppna `.env`. Byt `CHANGE_ME` mot era värden.
Serviceadresserna är exempel: kontrollera service, namespace och port i ert kluster.

| Fält | Vad du anger / var det finns |
| --- | --- |
| `NAMESPACE` | Projektet där boten ska köras, till exempel `cvebridge`. |
| `SCAN_NAMESPACES` | Projekt att skanna, till exempel `team-a,team-b`. |
| `STATE_NETWORK_URL` | Er delade nätverksmapp, exempelvis `//filserver.intern/bot-state` för SMB eller `nfs://server/export/bot-state` för NFS. Tomt använder klustrets standardlagring. |
| `MATTERMOST_INTERNAL_URL` | Mattermosts Service, till exempel `http://mattermost.mattermost.svc:8065`. |
| `MATTERMOST_BOT_TOKEN` | Mattermost-admin: Integrations → Bot Accounts → skapa bot med rollen Member → kopiera Access Token. Bjud in boten i den privata kanalen. |
| `MATTERMOST_COMMAND_TOKEN` | Integrations → Slash Commands → skapa `cve` med POST → kopiera Token. Request URL står nedan. |
| `MATTERMOST_CHANNEL_ID` | Be Mattermost-ansvarig hämta kanal-ID med `mmctl channel search --team devsecops team-security`. Byt team- och kanalnamn. |
| `MATTERMOST_KUBE_USER_MAP` | Nyckel = personens User ID i Mattermosts System Console → User Management → Users. Värde = samma persons exakta `oc whoami`. Lägg till alla människor i kanalen. |
| `STACKROX_URL` | Nåbar ACS Central-adress. `https://central.stackrox.svc:443` gäller när Central finns i samma kluster. |
| `STACKROX_CLUSTER_ID` | Be ACS-ansvarig hämta rätt klusters `id` från `GET /v1/clusters`. |
| De fyra `STACKROX_*TOKEN` | ACS: Platform Configuration → Integrations → Authentication Tokens → API Token → Generate Token. En separat token per rad. Roller nedan. |

Mappningen ska se ut så här, med era riktiga ID:n och konton:

```dotenv
MATTERMOST_KUBE_USER_MAP='{"CHANGE_ME_USER_ID":"CHANGE_ME_OPENSHIFT_USER"}'
```

För SMB behövs även lagringskontot eller en befintlig Secret. Se
[nätverkslagringen](NATVERKSLAGRING.md) för de få extra fälten och plattformens förutsättningar.

| Token | Behörighetsunderlag för ACS-ansvarig |
| --- | --- |
| `STACKROX_TOKEN` | Read: Deployment, Image, Cluster, Namespace. |
| `STACKROX_SCAN_TOKEN` | Read/Write: Image. |
| `STACKROX_STATUS_TOKEN` | Read: Administration för databasstatus. |
| `STACKROX_SCHEDULE_TOKEN` | Read: Deployment, Cluster, Namespace. Read/Write: Image. Scope begränsas till godkända schemanamespaces i valt kluster. |

ACS-ansvarig kontrollerar roller och scope-stöd i er version. Mappningen ger inte
människorna nya OpenShift-behörigheter. Spara tokens lokalt i `.env`.

## Hitta den Central som labbets Sensor redan använder

Om Sensor ligger i namespace `stackrox` kan du läsa den konfigurerade adressen:

```sh
oc -n stackrox get deploy sensor -o jsonpath='{.spec.template.spec.containers[*].env[?(@.name=="ROX_CENTRAL_ENDPOINT")].value}{"\n"}'
```

Använd motsvarande HTTPS-adress för Centrals API i `STACKROX_URL`, efter kontroll
med ACS-ansvarig. Boten behöver egna API-tokens och nätverksåtkomst även om Sensor
redan är ansluten. `STACKROX_CLUSTER_ID` ska vara labbklustrets ID i samma Central.

## Interna adresser räknas ut

Med `NAMESPACE=cvebridge` blir Mattermost-kommandots **Request URL**:

```text
http://cvebridge-webhook.cvebridge.svc:8001/slash/cve
```

Boten räknar också ut formulärens callback-adress. Ingen OpenShift Route skapas.
Mattermost-servern behöver kunna nå klustrets interna DNS och botens Service.
Om Mattermost blockerar interna integrationer godkänner admin just botens
servicevärd i `AllowedUntrustedInternalConnections`, enligt företagets policy.

Deployment-imagen blir automatiskt:

```text
image-registry.openshift-image-registry.svc:5000/<namespace>/cvebridge:<automatisk-tagg>
```

Push från en dator utanför klustret använder registryts externa route. Om din
byggmiljö når intern DNS kan du i stället sätta
`REGISTRY_PUSH_HOST=image-registry.openshift-image-registry.svc:5000`.

Fortsätt med [installationen](../START_HAR.md). Valfria undantag finns i
`.env.advanced.example`. Privat CA: spara publik PEM i `certs/` och ange
`STACKROX_CA_FILE=certs/central-ca.pem` när ACS kräver den.

Källor: [Mattermost botkonton](https://developers.mattermost.com/integrate/reference/bot-accounts/),
[slash-kommandon](https://developers.mattermost.com/integrate/slash-commands/custom/),
[interna integrationer](https://docs.mattermost.com/developers/integrate/plugins/interactive-messages),
[ACS-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token).
