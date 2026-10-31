# Privat installationsguide — företagets OpenShift

Den här guiden är ditt privata installationsunderlag och ingår inte i den
offentliga lokala guiden eller det publika publiceringspaketet. I den publika
projektkatalogen undantas filen från Git och containerbyggets kontext.
Den separata privata leveransen inkluderar guiden för ett privat GitHub-repo,
men innehåller inga verkliga lösenord eller token. Kör kommandona nedan från projektroten.

Den här guiden använder ett befintligt OpenShift-kluster, en befintlig Mattermost-bot
(exempelvis **OpenShift**) och befintlig ACS/RHACS Central. Den installerar ingen
ny Mattermost, ACS eller identitetsleverantör. Företagsprofilen använder OpenShifts
egen OAuth-server. Något live-test i OpenShift/OKD har ännu inte genomförts.

## Placering när Central finns på hubbklustret

För upplägget med gemensam ACS Central och sensorer i labb och produktion:

| Plats | Komponenter |
| --- | --- |
| Hubbklustret | Befintlig ACS Central med webbgränssnitt, API och databas. |
| Labbklustret | Befintlig Sensor och övriga lokala ACS-komponenter. Vår app och OAuth-proxy installeras i ett eget namespace här för att betjäna labbet. |
| Produktionsklustret | Befintlig Sensor och övriga lokala ACS-komponenter. En senare, separat appinstans kan betjäna produktionen. |
| Mattermost | Det befintliga botkontot, exempelvis **OpenShift**, och teamens kanaler. |

En appinstans använder målklustrets OpenShift-API för inloggning och behörigheter,
och hubbens Central-API för inventering, skanning och fynd. Den kontaktar inte
Sensor direkt. En gemensam app på hubben som betjänar andra kluster kräver
ytterligare stöd för kontroller mot varje målklusters API. Det stödet ingår ännu
inte; hubbens RBAC-rättigheter får inte användas som ersättning för labbets eller
produktionens rättigheter.

För labbinstallationen ska `stackrox_url` peka på **Central på hubben**, med en
adress och CA-kedja som fungerar från labbet. `stackrox_cluster_id` är samtidigt
**labbklustrets exakta ID i ACS**. OpenShift-kontexten vid installation ska vara
labbklustrets och `namespace` ska vara appens eget projekt där. Kontrollera att
ACS-kluster-ID:t motsvarar samma kluster som appens behörighetskontroller gäller.
`central.stackrox.svc` är ett klusterlokalt tjänstenamn och når inte automatiskt
Central i hubbklustret. Nätverksregler behöver tillåta appens anslutning till
Central och Mattermost, och Mattermosts anslutning till appens webhook.

## Eriks beställning, steg för steg

1. **Erik beställer i Mattermost:** `/cve scan team-a`.
2. **Boten ger Erik en privat länk** till appen. Länken gäller i tio minuter
   och är bunden till hans godkända konto.
3. **Proxyn leder till labbklustrets OpenShift-inloggning.** Erik loggar in
   med sitt vanliga konto eller använder sin befintliga giltiga session.
4. **Appen verifierar inloggningsbeviset mot OpenShift.** Den får Eriks
   verkliga användare och grupper och kontrollerar att han är beställaren.
5. **Appen hämtar namespaces och kontrollerar behörigheter i OpenShift.**
   Erik måste få lista `apps/deployments` i `team-a`. Delade beställningar
   begränsas dessutom av kanalens godkända omfattning och delningspolicy.
   Utan behörighet stoppas beställningen före ACS-anropet.
6. **Appen anropar ACS Centrals API på hubben**, avgränsat till labbklustrets
   ACS-ID och godkända namespaces. Den anropar inte Sensor direkt.
7. **ACS hanterar skanningen och svarar via Central.** Sensorernas befintliga
   koppling till Central ger klusterinventeringen; eventuella luckor redovisas.
8. **Appen kontrollerar åtkomst igen och skickar rapporten till Mattermost**,
   privat eller till godkänd privat kanal enligt beställningens delningsinställningar.

## Vem frågar och vem avgör behörigheten?

Det är **vår app bakom boten som ställer frågorna**. **OpenShift avgör vilka
namespace-behörigheter Erik har.** Botkontot är kontakten i Mattermost.

1. Mattermost ger appen det stabila användar-ID:t för kontot som beställde.
2. Erik loggar in via OpenShift. Appen verifierar inloggningsbeviset och att
   OpenShift-identiteten motsvarar den godkända mappningen för beställaren.
3. Appen hämtar namespace-listan från labbklustrets OpenShift-API och frågar
   för varje namespace om Erik får lista `apps/deployments` där. OpenShift
   svarar utifrån Eriks verifierade användare, grupper och aktuella RBAC-rättigheter.
4. Appen använder bara godkända namespaces, avgränsar dessutom enligt eventuell
   kanalpolicy och begär därefter skanning eller fynd via ACS Centrals API.

Central kan innehålla säkerhetsinformation om flera anslutna kluster och
namespaces. Det är appen som begränsar den aktuella beställningen till rätt
kluster-ID och tillåtna namespaces; ACS är inte källan till Eriks OpenShift-
behörigheter. ACS-token behöver också den avsedda begränsningen i ACS.

[Utvecklarnas offentliga bildguide](LOKALT_LABB.md#manuell-skanning) visar det lokala
Dex-labbet. Den här privata guiden beskriver OpenShift-profilen som ska verifieras.

## Hämta från ditt privata GitHub-repo

Den här privata guiden används tillsammans med projektets källkod och
installationsverktyg. Om du lägger projektet i ett privat repo kan du klona det
på datorn som når labbklustret, eller
ladda ner dess ZIP från GitHub. Börja i projektroten efter uppackning.
Det privata repot finns på https://github.com/SmidraClawd/cvebridge-openshift-private.
Du behöver vara inloggad med ett konto som har åtkomst för att ladda ner det.

Du behöver Python, `oc`, tillgång till ett godkänt containerregister, ett
befintligt OpenShift-labbkluster samt befintliga Mattermost- och ACS-tjänster.
Kontrollera målkontexten med `oc config current-context` innan du använder
installationskommandona. Den lokala k3d-demonstrationen verifierar inte
OpenShifts egen OAuth-inloggning.

## Förbered en privat konfigurationsfil

```bash
python3 scripts/company.py init --file .local/company.json
```

Fyll i filen lokalt. Den skapas med behörighet `0600` och skrivs aldrig över av
`init`. OAuth-klienthemligheten och en cookie-nyckel med 32 slumpbyte genereras.
Filen samlar adresser, appinställningar och token. Publicera den inte i Git.

| Fält under `settings` | Betydelse |
| --- | --- |
| `auth_provider` | `openshift` för denna startväg. |
| `namespace` | Projekt där appen ska köras. |
| `app_image` | Din byggda image, publicerad i ett register som klustret kan läsa. |
| `openshift_proxy_image` | OpenShift OAuth-proxy-image med version/digest godkänd för ert kluster. Använd inte den generiska OIDC-proxyn för denna profil. |
| `public_url` | Appens HTTPS-basadress, utan sökväg eller portnummer. |
| `webhook_public_url` | HTTPS-basadress för Mattermost-webhooken. Samma värde som `public_url` fungerar. Tomt värde skapar ingen extern webhook-Route. |
| `mattermost_public_url`, `mattermost_internal_url` | Webbläsarens respektive appens adress till samma Mattermost. |
| `stackrox_url`, `stackrox_cluster_id` | Central-adress och exakt ID för det anslutna secured cluster som ska användas. |
| `mattermost_channel_scopes` | Kanal-ID → godkända namespaces. Tomt objekt ger endast privata beställningar. |
| `mattermost_channel_policies` | Kanal-ID → `common` eller uttryckligen godkänd `requester`-delning. |
| `mattermost_schedule_scopes` | Kanal-ID → godkänd delmängd för automatiken. Tomt objekt stänger av schemaläggning. |
| `mattermost_schedule_managers` | Valfritt kanal-ID → lista med godkända Mattermost-ID:n för schemaändringar. |
| `schedule_default_timezone` | Exempelvis `Europe/Stockholm`. |
| `stackrox_scanner_component` | `SCANNER` eller `SCANNER_V4`, efter er installerade scanner. |
| `stackrox_delegate_scan` | `true` endast om delegerad skanning har konfigurerats i ACS. |
| `database_max_age_hours` | Tidsgräns för markeringen att CVE-underlaget är gammalt. |
| `cve_alerts_enabled` | `true` aktiverar engångsping med `@channel` i delade skanningsrapporter. |
| `cve_alert_min_cvss` | Larmgräns, normalt `9` för kritiska fynd. Sätt `0` för alla CVE:er. |
| `cve_alert_first_report` | Normalt `false`: första kompletta rapporten per namespace blir ett utgångsläge utan ping. `true` pingar även för befintliga fynd vid första rapporten. |

Ett exempel på teaminställningar, med verkliga ID:n ersatta av exempel:

```json
{
  "mattermost_channel_scopes": {"cccccccccccccccccccccccccc": ["team-a-dev", "team-a-prod"]},
  "mattermost_channel_policies": {"cccccccccccccccccccccccccc": "common"},
  "mattermost_schedule_scopes": {"cccccccccccccccccccccccccc": ["team-a-dev"]},
  "mattermost_schedule_managers": {"cccccccccccccccccccccccccc": ["aaaaaaaaaaaaaaaaaaaaaaaaaa"]}
}
```

Under `credentials` fyller du i följande:

| Nyckel | Användning |
| --- | --- |
| `MATTERMOST_TOKEN`, `MATTERMOST_BOT_ID` | Vanlig bot utan `system_admin`. Namnet är valfritt. `--online` kan läsa botens ID om fältet är tomt. |
| `SLASH_TOKEN`, `SLASH_ACS_TOKEN` | Token för `/cve` respektive `/acs`. Minst ett kommando krävs. Varje token ska vara unik och skild från botens token. |
| `MATTERMOST_KUBE_USER_MAP` | Objekt som kopplar stabilt Mattermost-användar-ID till exakt, skiftlägeskänsligt OpenShift-användarnamn. Exempel: `{"aaaaaaaaaaaaaaaaaaaaaaaaaa":"Alice"}`. |
| `STACKROX_TOKEN` | Begränsad läsåtkomst till inventering och fynd i avsett kluster. |
| `STACKROX_SCAN_TOKEN` | Separat behörighet för nya imageskanningar, Image `READ_WRITE_ACCESS` i avsett kluster. |
| `STACKROX_STATUS_TOKEN` | Administration `READ_ACCESS` för CVE-definitionernas uppdateringstid. |
| `STACKROX_SCHEDULE_TOKEN` | Separat inventerings-/scanbehörighet för automatiken. Krävs endast när scheman godkänts. |
| `OAUTH2_PROXY_CLIENT_SECRET`, `OAUTH2_PROXY_COOKIE_SECRET` | Genererade av `init`. Samma klienthemlighet används i OAuthClient och proxy-Secret. |

Identitetsmappningen godkänns administrativt, från tillförlitlig information om
vem kontona tillhör. Appen litar inte på ett självredigerat Mattermost-namn eller
en självredigerad profiladress. Alla mänskliga medlemmar i en delad kanal ska ha
mappningar. Botens ID är den enda publiken som undantas.

Fälten `stackrox_ca_file` och `mattermost_ca_file` ligger utanför `settings`.
Ange en PEM-fil med er CA-kedja; relativa sökvägar räknas från konfigurationsfilen.
Tomt värde använder CA-certifikaten från datorn som genererar installationen.
De läggs i en Secret så att appen kan verifiera tjänstens TLS-certifikat.
Mattermost får en separat CA-Secret när en egen CA-fil anges.

## Bygg appens image

Bygg från projektroten med den befintliga `.dockerignore`-filen:

```bash
docker build -f app/Dockerfile -t DITT-REGISTER/cvebridge:DITT-VERSIONSNAMN .
docker push DITT-REGISTER/cvebridge:DITT-VERSIONSNAMN
```

Sätt `app_image` till den publicerade versionen eller dess digest. Ordna vid behov
registrets vanliga pull-Secret i appens projekt. Ingen publicerad företagsimage
levereras automatiskt av detta projekt.

`prepare` skapar också `app-source.tar.gz` som byggkontext: endast Dockerfile och
de tre Python-filerna i `app/` ingår. Den kan skickas till en godkänd binär
OpenShift-build med Docker-strategi. Skicka inte hela projektkatalogen som binärt
buildunderlag eftersom den kan innehålla privata filer i `.local`.

## Kontrollera och generera

```bash
python3 scripts/company.py check --file .local/company.json
python3 scripts/company.py prepare --file .local/company.json
```

Dessa kommandon gör inga nätverksanrop och ändrar inget kluster. Kontrollen
validerar format och obligatoriska inställningar, inte faktisk anslutning.
Med `--online` görs en GET mot det konfigurerade Mattermosts `/api/v4/users/me`
för att kontrollera boten och läsa dess ID om det saknas. Bot-ID:t används i de
genererade installationsfilerna; originalkonfigurationen skrivs inte om.
Ingen Mattermost-administratörstoken behövs och inga meddelanden skickas.

Under `.local/company-install/` skapas:

- `install.json`: Namespace, Secrets, OAuthClient och alla driftsresurser. **Innehåller hemligheter.**
- `deployment.json`: resurser för granskning utan Secrets och OAuthClient.
- `app-source.tar.gz`: begränsat byggunderlag utan konfigurationsfiler eller token.

Alla tre filer skrivs med behörighet `0600`. Kör `prepare` igen efter ändringar.
Generatorn skapar bara appens projekt; teamens namespaces ska redan finnas.

## Installera i ett avsett testprojekt

Som OpenShift-admin, granska resurserna och välj målkontext uttryckligen:

```bash
oc --context DITT-TESTKONTEXT apply -f .local/company-install/install.json
oc --context DITT-TESTKONTEXT -n DITT-PROJEKT rollout status deployment/cvebridge
```

Detta är den manuella installationspunkten. Projektet ansluter inte automatiskt
till något företagskluster. En lokal provkörning behöver ingen företagsanslutning.

Generatorn skapar en PVC och en enda appreplika med proxy i samma pod. Backend
lyssnar endast på loopback-port 8000 och får ingen Service. Browser-Route går
via proxyn på 4180. Webhook-Route går enbart till lyssnaren på 8001 och sökvägen
`/slash/cve`; den kräver kommando-token och erbjuder inga webbsidor.
App och proxy tappar capabilities, saknar privilege escalation och använder
skrivskyddat rotfilsystem. OpenShifts SCC väljer UID och fsGroup. Ge inte appen
`anyuid` eller en privilegierad SCC. `/data` ligger på PVC:n.

## Så fungerar OpenShift-inloggningen

1. Proxyn använder en registrerad OpenShift `OAuthClient`, med callback
   `PUBLIC_URL/oauth2/callback`, och begär endast `user:info`.
2. Utvecklaren loggar in via klustrets OAuth-server och godkänner klienten.
3. Proxyn skickar OAuth-token vidare internt till appen. Appen verifierar token
   med klustrets TokenReview API och använder dess exakta användare och grupper.
4. Appen gör SubjectAccessReview för `list` på `apps/deployments` i varje namespace.
   Denna policy avgör vilka namespaces personen får använda i tjänsten.
5. En Mattermost-beställning binds till det godkända OpenShift-kontot och dess
   stabila Mattermost-ID. Inloggning som någon annan ger avslag.

Appen använder inte påstådda `X-Forwarded-User`, e-post eller gruppheaders som
bevis i denna profil. Personliga token sparas inte i jobb, SQLite eller rapporter.
De används till TokenReview under pågående manuella jobb; återkallad token eller
namespace-åtkomst stoppar fortsatt arbete och leverans vid nästa kontroll.
Automatiken använder en separat reporteridentitet och ACS-token.

Appens ServiceAccount får lista namespaces och skapa SubjectAccessReview samt
TokenReview. Det får inte `impersonate` eller allmän pod-/Secret-läsning.
Proxyn får en separat, begränsad Role i `openshift-config-managed` för att läsa
ConfigMap `oauth-serving-cert`, för proxyversioner som använder den CA-upptäckten.
Klient- och cookiehemligheter monteras från en Secret. En uttrycklig OAuthClient
används så klienthemligheten inte är beroende av ett roterande ServiceAccount-token.
Välj proxy-image efter er klusterversion och kontrollera dess startflaggor.

Se [OpenShift OAuth-proxy](https://github.com/openshift/oauth-proxy) och dess
[providerimplementation](https://github.com/openshift/oauth-proxy/blob/master/providers/openshift/provider.go).

En separat extern OIDC-profil finns kvar i `config/openshift.example.json` och
renderas med `scripts/platform.py render --config FIL`. Där krävs ett riktigt
OIDC-klient-ID, issuer och godkänd e-post-/Kubernetes-mappning. Det är ett annat
inloggningsläge än företagsstartens `auth_provider: openshift`.

## Mattermost: befintlig bot utan admin

Lägg din befintliga bot i deltagande team och privata kanaler. Den behöver vanliga
rättigheter att läsa deltagande konton och kanalmedlemskap, skapa inlägg och ladda
upp rapportfiler. Appen verifierar exakt bot-ID, `is_bot` och avsaknad av
`system_admin`. Den behöver inte post-all-roller. Namnet får exempelvis vara
**OpenShift**; vissa texter i resultatkorten använder fortfarande produktnamnet ACS.

Registrera `/cve` och/eller `/acs` som POST till
`https://DIN-WEBHOOK-ADRESS/slash/cve`. Om Mattermost finns i samma klusternät kan
`http://cvebridge-webhook.DITT-PROJEKT.svc:8001/slash/cve` användas och
`webhook_public_url` lämnas tomt. Kommando-triggern är oberoende av botnamnet;
`/openshift` är inte ett implementerat alias. Tokens för de två stödda kommandona
är separata. Aktivera inga breda interna nätundantag; eventuell serverallowlist
måste tillåta det avsedda webhook-värdnamnet.

Serverinställningar för integrationer och visuella namn-/ikonöverskrivningar kan
kräva Mattermost-admin. Det ändrar inte vem som faktiskt skriver delade rapporter:
de publiceras med din befintliga bots vanliga REST-token.
Det lokala `scripts/onboard.py` använder en labbadministratör och är inte
företagsvägen för en Mattermost-operatör utan adminroll.
Se [kommandon](https://docs.mattermost.com/developers/integrate/slash-commands/custom)
och [integrationsinställningar](https://docs.mattermost.com/administration-guide/configure/integrations-configuration-settings).

## Delning och scheman

`common` kontrollerar varje aktuell mänsklig kanalmedlem med exakt användarnamn
och `system:authenticated`. Det hämtar inte grupper för andra medlemmar som inte
är inloggade. Gruppbaserade bidrag ensamma räcker därför inte för den delningspolicyn.
Den inloggade personens privata åtkomst använder däremot TokenReviews grupper.

`requester` kräver att operatören uttryckligen godkänner kanalen som mottagare av
beställarens resultat. Omfattningen är beställarens aktuella åtkomst skuren mot
kanalens godkända namespace-lista. Alla medlemmar måste fortfarande ha verifierade
kontomappningar. Befintliga delade inlägg och bilagor ligger kvar i historiken och
kan läsas av framtida medlemmar; godkänn kanalmedlemskap och retention därefter.
Medlemskontroll och publicering i olika system är inte atomiska.

Scheman får en separat `acs-reporter`-ServiceAccount med `list apps/deployments`
endast i uttryckligen godkända namespaces. Ingen token monteras för den identiteten;
appens reviewer-konto kontrollerar dess behörigheter med SubjectAccessReview.
`STACKROX_SCHEDULE_TOKEN` används för inventering/skanning vid automatiska körningar.
Ingen personlig webbinloggning behövs när schemat körs. Se
[SCHEDULING.md](docs/SCHEDULING.md) för tider, begränsningar och körhistorik samt
[README:s bildguide](LOKALT_LABB.md#automatiska-korningar) för utvecklarnas steg.

## Verifiera före företagsdrift

Lokala tester validerar kod och resursgenerering. Den verkliga OpenShift-kedjan
är fortfarande oprövad. I ett avsett OpenShift-/OKD-testkluster behöver följande
kontrolleras med två vanliga användare och olika namespace-rättigheter:

- Inloggning, godkännande och callback med den valda proxy-imagen och CA-kedjan.
- Rätt användare/grupper från TokenReview och rätt namespace-lista från SAR.
- Avslag för en annan persons länk, utgången/återkallad token och återkallade RBAC-rättigheter.
- Kommando, manuell skanning, specifik CVE, fullständig rapportbilaga och rätt kanalpublik.
- Schema, verklig tidsstyrd körning, provkörning, paus och beständig historik efter omstart.
- App-UID/PVC under SCC, resursbehov, registryåtkomst, nätverk och tokenrotation.

En instans använder ett exakt ACS-kluster-ID och kan betjäna flera teamkanaler.
Integrationen är specifik för Mattermost och ACS/StackRox, inte en adapter för
alla scanners. Sensor måste ha inventering för det valda klustret. Nya skanningar
kräver åtkomst till images via Centrals registryintegration eller korrekt
konfigurerad delegerad skanning. Images som inte stöds eller misslyckas markeras;
ett tomt fyndresultat bevisar inte att miljön saknar sårbarheter.

## Alternativ för att verifiera OpenShift-kopplingen lokalt

| Miljö | Vad den kan verifiera | Resurser och skillnader |
| --- | --- | --- |
| Vårt befintliga k3d-labb med Dex | Mattermost, manuell skanning, CVE-sökning, RBAC och schemalagda rapporter. | Körs lokalt redan. OpenShifts egen OAuth-koppling ingår inte i det testet. |
| MicroShift | Appdrift, Routes och Kubernetes-behörigheter när nödvändiga komponenter konfigurerats. | CRC anger minst 2 CPU, 4 GB RAM och 35 GB disk. En separat IdP, exempelvis Dex, kan läggas till; det verifierar inte automatiskt OpenShift OAuth. |
| OpenShift Local eller OKD via CRC | En lokal miljö med den inbyggda OpenShift-/OKD-inloggningen. | Minst 4 fysiska CPU-kärnor, 10,5 GB ledigt RAM och 35 GB disk för CRC-miljön; våra tjänster behöver utrymme och minne utöver detta. |
| App lokalt + ett befintligt OpenShift-testkluster | Riktig OpenShift-inloggning utan ett helt kluster på datorn. | Kräver nätåtkomst/VPN, en registrerad testklient, korrekt callback och behörigheter i det befintliga klustret. Detta upplägg är ännu inte färdigt eller provkört i projektet. |

Kontrollerat 2026-10-31 mot [CRC:s systemkrav](https://crc.dev/docs/installing/),
[CRC:s profiler](https://crc.dev/docs/using/) och
[Red Hats jämförelse av MicroShift och OpenShift](https://redhatquickcourses.github.io/rhde-microshift-bootc/rhde-microshift-bootc/1/ch2-package/s1-install-config.html).
CRC stöder inte Debian officiellt; manuell värdkonfiguration kan behövas.
Ett [dokumenterat MicroShift/Dex-exempel](https://www.aleskandro.com/posts/fedora-coreos-microshift/)
och ett [exempel med lokal app och klustrets OAuth](https://github.com/rh-aiservices-bu/sardeenz/blob/main/docs/dev-setup.md)
visar de två senare inloggningsuppläggen. De är referenser, inte genomförda tester
av den här appen. Ingen ny miljö har installerats för dessa alternativ.
