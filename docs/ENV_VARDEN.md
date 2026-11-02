# Fyll i .env – 11 fält

Kör `./cvebridge.sh init` för att skapa `.env`. En befintlig fil skrivs inte över.
Du fyller själv i företagets värden lokalt.
Serviceadresserna är exempel och ska stämma med era installationer.

| Fält | Det du anger |
| --- | --- |
| `NAMESPACE` | Projektet där både boten och er färdiga PVC finns. |
| `STATE_EXISTING_PVC` | Namnet på PVC:n. Se `oc get pvc -n ert-projekt`. |
| `SCAN_NAMESPACES` | Projekt att skanna, exempelvis `team-a,team-b`. |
| `MATTERMOST_INTERNAL_URL` | Er Mattermost-adress som boten kan nå. |
| `MATTERMOST_BOT_TOKEN` | Botkontots Access Token. |
| `MATTERMOST_COMMAND_TOKEN` | Token från registreringen av `/cve`. |
| `MATTERMOST_CHANNEL_ID` | Rapportkanalens ID. |
| `MATTERMOST_KUBE_USER_MAP` | Varje persons Mattermost-ID kopplat till samma persons OpenShift-användarnamn. |
| `STACKROX_URL` | Nåbar HTTPS-adress till ACS Central. `.svc` fungerar inom samma kluster. |
| `STACKROX_CLUSTER_ID` | Labbklustrets ID i ACS Central, från ACS-ansvarig eller `/v1/clusters`. |
| `STACKROX_TOKEN` | En API-token för botens läsning, skanning, databasstatus och scheman. |

Botens callback, reporteridentitet, imageadress och image-tagg räknas ut.
Databasen monteras på `/data/requests.sqlite3` via PVC:n. Ingen lagrings-Secret
behövs i botinstallationen för en färdig PVC.

Har du en äldre `.env` med fyra ACS-token? Behåll dina värden. De tre extra
tokenraderna kan tas bort när den gemensamma `STACKROX_TOKEN` har rättigheterna
som beskrivs nedan.

## Var tokenen finns

- **Mattermost bot:** admin öppnar Integrations → Bot Accounts → Add Bot Account.
  Välj Member och kopiera Access Token. Bjud in boten i kanalen.
- **Mattermost kommando:** Integrations → Slash Commands → registrera `cve` med
  POST enligt [installationen](INSTALLATION.md), spara och kopiera Token.
- **ACS:** Platform Configuration → Integrations → Authentication Tokens →
  API Token → Generate Token. Välj rollen som ACS-ansvarig har godkänt för boten.

Den gemensamma ACS-tokenens roll behöver Read på Deployment, Image, Cluster,
Namespace och Administration (för databasstatus), samt Write på Image (för
skanningsbeställningar). ACS-ansvarig verifierar rättigheter och access scope i
er version. Begränsa åtkomsten till avsedd omfattning. Mänskliga användares
namespace-behörighet kontrolleras dessutom i Kubernetes för varje beställning.

Separata `STACKROX_SCAN_TOKEN`, `STACKROX_STATUS_TOKEN` och
`STACKROX_SCHEDULE_TOKEN` går fortfarande att ange som uttryckliga undantag.
De behövs inte i grundfilen. Övriga valfria inställningar finns i
[env-options.example](env-options.example).

## Användarmappningen med ett exempel

Om Anna har Mattermost-ID `h8k3m2p9r7t6v5x4z1a0b2c3d4` och `oc whoami` visar
`anna`, anger du:

```dotenv
MATTERMOST_KUBE_USER_MAP='{"h8k3m2p9r7t6v5x4z1a0b2c3d4":"anna"}'
```

Det betyder att personen med detta Mattermost-ID är OpenShift-användaren `anna`.
Mattermost-admin hittar personens ID i System Console → User Management → Users.
Varje person hämtar sitt eget OpenShift-användarnamn med `oc whoami`.
Lägg till en koppling per mänsklig medlem i rapportkanalen. Mappningen ger inga
nya klusterbehörigheter; [åtkomstmodellen](ACCESS.md) beskriver kontrollen.

Sensorn rapporterar klusterdata till Central. Boten anropar Centrals API, även
när Central finns i ett annat kluster. Ange då den Central-adress som boten kan nå.

Källor: [Mattermost botkonton](https://docs.mattermost.com/developers/integrate/reference/bot-accounts),
[användar-ID](https://docs.mattermost.com/administration-guide/configure/user-management-configuration-settings#identify-a-users-id),
[ACS API-token](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/configuring/configure-api-token).
