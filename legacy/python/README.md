# ACS — CVE Bridge for Mattermost

Beställ containerskanningar och undersök CVE:er direkt från Mattermost.
ACS-boten visar korta svenska rapporter med risknivå, tre prioriterade fynd
och en tydlig **Åtgärd**-rad. Hela skanningsrapporten bifogas som JSON.

Projektet innehåller ett reproducerbart lokalt labb med riktig Mattermost,
PostgreSQL, Dex, OAuth2 Proxy, Kubernetes RBAC och StackRox Central/Scanner/Sensor.
Resultaten kommer från skannern. Beställningar begränsas av användarens
verifierade identitet, namespace-behörigheter och kanalens godkända omfattning.

**ACS** är botkontot; Alice och Bob är labbets utvecklarkonton. Både `/cve`
och `/acs` stöder manuell skanning, CVE-sökning och schemalagda rapporter.
En ny kritisk CVE kan ge en `@channel`-ping en gång per kanal och kluster.
Den första fullständiga rapporten skapar normalt ett utgångsläge utan ping.

Tjänsten ansluts till en godkänd privat teamkanal. Se
[teamanslutning](docs/TEAM_ONBOARDING.md) för arbetsflödet.

Den här README:n beskriver det lokalt installerade labbet och dess verifierade
användarflöden. För utvecklare: följ bildguiden nedan. För lokal installation, se
[START_HAR.md](START_HAR.md).

## Börja här: utvecklarguide med skärmbilder

Den här guiden följer ett team från första anslutningen till manuella och
automatiska rapporter. Bilderna visar den riktiga lokala installationen med
utvecklarkontot **Alice**, boten **ACS** och de privata demokanalerna
**ACS Onboarding** och **ACS Rapporter**. Den tidsstyrda testkörningen visas i
**Team Security**.
Byt exempelns namespace och adresser mot dem som plattformsteamet har godkänt
för ert team. Ni behöver ingen egen installation av ACS per utvecklare.

Gå direkt till [manuell skanning](#manuell-skanning),
[specifik CVE](#specifik-cve), [automatiska körningar](#automatiska-korningar)
eller [ändra och pausa](#andra-eller-pausa).

### Snabbreferens

| Jag vill … | Skriv i teamets Mattermost-kanal | Vad händer? |
| --- | --- | --- |
| Se hjälp | `/cve help` | Visa kommandon och hur tjänsten fungerar. |
| Kontrollera CVE-databasens ålder | `/cve status` | Läs den uppdateringstid som StackRox rapporterar. |
| Skanna ett namespace nu | `/cve scan demo-team-a` | Starta nya imageskanningar och få en rapport. |
| Skanna alla namespaces som är tillåtna för min beställning | `/cve scan` | Samma manuella flöde, med bredare tillåten omfattning. |
| Undersöka en specifik CVE | `/cve CVE-2021-44228 demo-team-a` | Sök den CVE:n i befintliga skanningsresultat. |
| Ställa in, ändra eller pausa automatiska körningar | `/cve schedule` | Öppna teamets formulär direkt i Mattermost. |

`/acs` fungerar som alias för `/cve`. En manuell beställning kräver inget
automatiskt schema och ändrar inte ett befintligt schema.

### Korta svenska svar

Hjälp, beställning, resultat, schema och fel använder samma kortformat. Rapporten
visar högst tre prioriterade CVE:er; alla fynd finns kvar i JSON-bilagan.
Varningar om saknade skanningar och gammalt CVE-underlag döljs inte.

![Svensk snabbhjälp i den riktiga Mattermost-kanalen](assets/reports/01-snabbhjalp.jpg)

![Kort statusbesked med CVE-databasens ålder](assets/reports/06-databasstatus.jpg)

![Begripligt felkort när CVE-numret är felstavat](assets/reports/07-felmeddelande.jpg)

### 1. Anslut teamet en gång

1. **Teamet beställer ACS-tjänsten** till en ny eller befintlig privat
   Mattermost-kanal och anger vilka kluster och namespaces som hör till teamet.
2. **Plattformsteamet förbereder anslutningen:** kontrollerar att klustret är
   anslutet till StackRox, godkänner kanalens namespaces och delningspolicy,
   verifierar identiteter och åtkomst och lägger till den befintliga ACS-boten.
3. **Plattformsteamet godkänner automatiken** för kanalen om teamet ska kunna
   schemalägga körningar. Vid behov utses särskilda personer som får ändra schemat.
4. **Utvecklarna öppnar kanalen** och följer något av flödena nedan. De behöver
   ingen administratörsroll i Mattermost och lämnar inga egna API-token till boten.

Beställningen och operatörens godkännande sker enligt er vanliga process.
Skapandet av en kanal är inte en automatisk anslutning till ACS. Det lokala
administrationsverktyget och dess kontroller beskrivs i
[teamanslutning](docs/TEAM_ONBOARDING.md); någon företagsportal eller
ärendehanteringsintegration ingår ännu inte.

<a id="manuell-skanning"></a>

### 2. Kör en manuell skanning

**Steg A — beställ i kanalen.** Skriv exempelvis följande och tryck Enter:

```text
/cve scan demo-team-a
```

Det angivna namespacet avgränsar just den här beställningen. Utelämna namnet
om alla namespaces som är tillåtna för beställningen ska ingå.

**Steg B — öppna den privata länken.** ACS svarar med **Logga in och starta
imageskanning**. Svaret syns bara för beställaren. Länken gäller i tio minuter
och är bunden till samma användare; den ska inte delas med en kollega.

![ACS lämnar en privat inloggningslänk och beskriver var resultatet delas](assets/reports/02-bestallning.jpg)

**Steg C — logga in som dig själv.** I labbet används Dex och kontot
`alice@demo.local`; lösenordet finns i den privata lokala lösenordsfilen.
Är du redan inloggad kan du komma direkt till skanningen.

![Labbets inloggningsformulär, utan ifyllt lösenord](assets/onboarding/03-inloggning.jpg)

**Steg D — följ skanningen.** När den privata länken öppnas och inloggningen är
godkänd startar skanningen. Sidan uppdateras automatiskt och visar när den är
klar, vilka namespaces som ingick och eventuella misslyckanden.

![Slutförd manuell skanning med omfattning och länk till rapporten](assets/reports/11-skanning-webb.jpg)

<a id="rapportformat"></a>

**Steg E — läs rapporten i kanalen.** ACS publicerar ett vanligt botinlägg i
den godkända teamkanalen. Det kompakta kortet visar omfattning, riskfördelning,
högst tre prioriterade CVE:er och en **Åtgärd**-rad. Fixversioner märks som
skannerns underlag och ska kontrolleras mot aktuell leverantörsinformation.
Teamet behöver därefter bygga om och rulla ut
berörda containerbilder och kontrollera resultatet med en ny skanning.
Kanalmedlemmarna kan läsa inlägget utan att öppna beställarens privata länk.

![Aktuellt svenskt rapportkort med åtgärd, täckning och JSON-bilaga](assets/reports/04-skanningsrapport.jpg)

Hämta **acs-scan-report.json** för samtliga rapporterade fynd, inklusive
berörda appar, pakettyper och versioner. I en kanal som inte är godkänd för
delning levereras resultatet privat till beställaren.

**Bevakning av nya fynd:** när nästa manuella eller automatiska rapport hittar
en tidigare orapporterad CVE med CVSS minst 9 kan boten pinga `@channel` en gång.
Samma CVE pingar inte igen efter omstart eller när fyndet återkommer. Ett nytt
namespace får först ett eget utgångsläge utan massping. Detta är bevakning vid
rapportkörning, inte en separat realtidsström av nya CVE-publiceringar.
Larmgräns och första rapportens beteende kan konfigureras.

![Engångslarm med en riktig kanalmention i den privata demokanalen](assets/reports/03-engangslarm.jpg)

Larmbilden demonstrerar alternativet att pinga även i första rapporten, med
riktiga befintliga labbfynd. Standardläget börjar utan ping. Vid kontrollen
ökade Bobs notisräknare en gång; samma CVE:er i nästa rapport gav ingen ny
mention. Mattermost-medlemmar kan själva välja att ignorera kanalmentions.
E-post och mobilpush har inte verifierats i labbet.

| Inställning | Standard | Anpassning |
| --- | --- | --- |
| `cve_alerts_enabled` | `true` | Stäng av massping med `false`. |
| `cve_alert_min_cvss` | `9` | Kritiska fynd; välj `0` för alla CVE:er. |
| `cve_alert_first_report` | `false` | Sätt `true` om även första rapportens befintliga fynd ska pinga. |

Operatören anger dessa värden i installationsinställningarna. Historiken ligger
på appens beständiga lagring. En CVE-sökning, hjälpsvar eller statusrapport pingar
inte kanalen. Läs [driftsgränserna](docs/SCHEDULING.md#new-cve-mentions) för
leveransavbrott och lagringsbyte.

<a id="specifik-cve"></a>

### 3. Sök en specifik CVE

När ni har fått ett CVE-nummer kan ni undersöka just det fyndet:

```text
/cve CVE-2021-44228 demo-team-a
```

Följ den privata länken **Logga in och visa CVE-2021-44228** och logga in på
samma sätt som vid manuell skanning. ACS svarar med berörda appar, paket,
installerad version, tillgänglig fixinformation och risknivå.

![Ett kompakt svar för en specifik CVE i Mattermost](assets/reports/05-cve-svar.jpg)

**CVE-sökning läser befintliga skanningsresultat.** Kör `/cve scan demo-team-a`
först om ni behöver en ny skanning och sök sedan på CVE-numret. Utan namespace
i CVE-kommandot söker tjänsten inom hela den omfattning som är tillåten för
beställningen.

Det finns också ett webbformulär på tjänstens adress, i labbet
`http://localhost:18080`: skriv CVE-numret, välj namespace i listan och klicka
**Sök i StackRox**. Den här direkta webbsökningen visar resultatet i webbläsaren;
använd Mattermost-kommandot när resultatet ska publiceras i teamkanalen.

![Webbformulär med ett CVE-nummer och valt namespace](assets/onboarding/15-cve-formular.jpg)

![Webbresultat med berörd Java-app och paketinformation](assets/onboarding/17-cve-webbresultat.jpg)

CVE-numret skrivs i kommandot eller fältet. En klickbar lista över CVE:er finns
ännu inte. Det automatiska schemat har heller inget filter för ett enskilt
CVE-nummer; dess rapport omfattar fynden från valda namespaces.

<a id="automatiska-korningar"></a>

### 4. Ställ in automatiska körningar

**Steg A — öppna inställningarna.** Kör följande i teamets godkända kanal:

```text
/cve schedule
```

Kommandot öppnar **Teamets schema** som en dialogruta direkt i Mattermost.
Du fyller i fälten här; ingen extern sida eller separat webbinloggning behövs
för schemainställningarna. Dialogrutan visas bara för personen som körde kommandot.

![Schemaformuläret direkt i Mattermost med dagar, tider och godkända namespaces](assets/native-schedule/01-schema-i-mattermost.jpg)

**Steg B — välj vad och när.** Anpassa formuläret, till exempel så här:

| Fält | Exempel | Betydelse |
| --- | --- | --- |
| Veckodagar | Måndag–fredag | Välj en eller flera dagar. |
| Tider | `08:00, 15:00` | Högst fyra tider per dag och minst en timme mellan. |
| Tidszon | `Europe/Stockholm` | Tiderna tolkas i den valda tidszonen. |
| Namespaces | `demo-team-a` | Välj bland godkända alternativ. Minst ett krävs. |
| Vad ska göras? | Ny skanning och rapport | Alternativet med befintliga fynd hämtar en rapport utan att skanna om. |
| Efter sparning | Aktiverat | Välj Pausat om schemat inte ska köras ännu. |
| Åtgärd | Spara inställningar | Andra alternativ blir tillgängliga när ett schema finns. |

**Steg C — välj Spara inställningar och klicka Utför.** Boten bekräftar dagar,
tider, namespaces och nästa körning i kanalen. Nästa körning visas i UTC;
exempelvis motsvarar 07:00 UTC klockan 08:00 i Stockholm under vintertid.
Inga automatiska körningar aktiveras före första sparningen.

**Behöver man vara admin?** Nej. Godkända teammedlemmar kan använda formuläret,
eller bara utsedda schemaansvariga om operatören har begränsat redigeringen.
Mattermost-admin behövs normalt bara för den ursprungliga anslutningen och
kommandoregistreringen. Ingen särskild formulärfunktion behöver aktiveras per kanal,
men kanalen ska vara godkänd för schemaläggning. Boten behöver ingen adminroll.

![ACS bekräftar det sparade schemat i Mattermost](assets/reports/08-schema-bekraftelse.jpg)

**Steg D — ta emot rapporten automatiskt.** Vid starttiden kör tjänsten det
sparade jobbet och publicerar rapport och JSON-bilaga i kanalen. Ingen behöver
vara personligen inloggad vid körningen. Applikationen, klustret och de tjänster
som behövs måste vara igång.

![Rapport från en verklig tidsstyrd körning i demokanalen](assets/reports/10-automatisk-rapport.jpg)

Bilden ovan kommer från en verklig tidsstyrd testkörning vid en tillfälligt vald
tid. Den visar samma leveransflöde som schemat med klockan 08 och 15.

<a id="andra-eller-pausa"></a>

### 5. Ändra, provkör eller pausa

Kör `/cve schedule` igen. Samma dialogruta visar det sparade schemat.
Välj vad du vill göra under **Åtgärd** och klicka **Utför**:

- **Spara inställningar:** ändra dagar, tider, tidszon, körningstyp, namespaces eller status.
- **Provkör sparat schema:** kör det redan sparade schemat. Osparade ändringar används inte.
- **Pausa sparat schema:** pausa automatiken utan att ändra det sparade urvalet.
- **Visa körhistorik:** få de senaste körningarna som ett privat svar i Mattermost.

För att återuppta väljer du **Efter sparning: Aktiverat**, sedan **Spara inställningar**.

![Val för att spara, pausa, provköra och läsa historik i samma Mattermost-formulär](assets/native-schedule/02-atgarder-i-formularet.jpg)

Schemat tillhör kanalen. Verifierade teammedlemmar får ändra det om inte
operatören har begränsat redigeringen till utsedda schemaansvariga. En kollega
kan bevara teamets redan godkända omfattning vid en tidsändring; utökning till
ett namespace kräver ytterligare åtkomstkontroll. Två samtidiga ändringar
skyddas mot att ett gammalt formulär skriver över ett nyare.

### 6. Förstå omfattningen och rapporten

**Urvalet görs per namespace.** Inom valda namespaces undersöks images som används
av aktiva poddar i StackRox Sensors inventering vid start, inklusive kända
init-container-images. Hela containerregistret och oanvända images ingår inte.
Det finns ännu inget val av enskilda appar eller images inom ett namespace.

Skannern kan hitta stödda OS-paket och språkberoenden, exempelvis Java-bibliotek
i JAR-filer. Egen källkod och externa tjänster ingår inte i imageskanningen.
JSON-rapporten visar typ av paket, men delar ännu inte automatiskt upp ägarskapet
mellan basimage och applikationslager. Drift och utvecklare uppdaterar sina
respektive beroenden, bygger om berörda images och deployar dem; tjänsten patchar
inte paketen åt dem.

Läs alltid täckning, misslyckade eller saknade skanningar och databasens ålder.
Ett tomt resultat är inte ett bevis på att miljön är fri från sårbarheter.
Databasen i dessa labbilder är markerad som gammal. Bildernas paketversioner
och fixinformation återger det dåvarande skanningsunderlaget, inte en aktuell
rekommendation om vilken version ett team ska deploya.

### Om något inte fungerar

| Det du ser | Nästa steg |
| --- | --- |
| Länken har gått ut eller redan använts | Kör kommandot igen och använd den nya privata länken. |
| Fel konto eller nekad åtkomst | Logga in som beställaren. Be plattformsteamet kontrollera befintlig behörighet och kanalens godkända omfattning om felet kvarstår. |
| Schemaläggning är inte tillåten i kanalen | Be plattformsteamet godkänna schemaläggning för rätt privat kanal. |
| Formuläret säger att schemat har ändrats | Kör `/cve schedule` igen, läs de senaste inställningarna och gör ändringen där. |
| En rapport saknas | Öppna **Visa schema och körningar** efter sparning och läs körhistoriken. Kontrollera också kanal, aktivering, veckodag och tidszon. |
| En körning misslyckades eller missades under avbrott | Läs körhistoriken och be drift kontrollera tjänsterna. Gamla körningar spelas inte upp som en kö efter ett längre avbrott. |
| Gammal databas, ofullständig täckning eller misslyckade images | Låt plattformsteamet kontrollera uppdatering, inventering och skanneranslutning innan resultatet används som fullständigt underlag. |

### Om bilderna och labbverifieringen

Skärmbilderna är tagna från den körande installationen den 31 oktober 2026.
Manuell skanning, CVE-sökning, första sparning, ändring, tidsstyrd leverans,
provkörning och paus har kontrollerats i demokanalen. Bilderna innehåller inga
lösenord eller API-token. Demokanalens schema lämnas pausat efter genomgången.
Den vanliga testkanalen **Team Security** har sitt eget separata schema.
De aktuella Mattermost-korten visas ovan. Formulär- och körhistorikbilderna
kommer från den tidigare genomgången av samma lokala flöde.

## Verifierad projektstatus

Det lokala labbet är verifierat med 102 enhetstester, verkliga manuella
skanningar och rapportleveranser samt tidsstyrda körningar. Resultaten sparas
lokalt under `.local/` och följer inte med i Git. Skärmbilden ovan visar en
verklig rapport från den 31 oktober 2026.

Detta är ett demonstrationsprojekt med en appreplik. Skannerns databas var
markerad som gammal vid genomgången; fynd och fixversioner i bilderna är
exempel från det underlaget. Använd projektet som ett lokalt labb och verifiera
en anpassad installation innan den tas i drift.

För operatörer finns mer om [lokal teamanslutning](docs/TEAM_ONBOARDING.md)
och [schemaläggning och driftsgränser](docs/SCHEDULING.md). Resten av README
beskriver lokal installation, kommandon och teknisk drift.

## Run locally

Requirements: Docker, k3d 5.9+, kubectl, Helm 3+, Python 3.10+, and the Python
packages `bcrypt` and `requests`. Docker must be running and accessible. On this
Linux installation the installer can use an existing passwordless `sudo` grant
for Docker/k3d; it does not change Docker socket permissions or group membership.
On Windows, run the scripts in WSL2 with Docker integration enabled.

Budget at least 16 GB system RAM, about 8 GB available for the lab, and at least
25 GiB free disk (30 GiB recommended) for downloads, image layers, vulnerability data, and temporary indexes
during the first database import. These are lab
budgets, not vendor production sizing recommendations. First startup requires
internet access to image registries and StackRox vulnerability feeds; application
services and test data run locally. This is not an air-gapped installer.

The installation has been exercised on Linux/amd64. Other hosts need compatible
upstream container images and have not been validated by this local test report.
On slower disks, the first vulnerability database import can take tens of minutes;
subsequent starts reuse the persistent database.

```bash
git clone https://github.com/SmidraClawd/cvebridge.git
cd cvebridge
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-bootstrap.txt
python scripts/platform.py up
```

The installer creates only its own `cvebridge` k3d cluster and writes its own
`.local/kubeconfig`. It leaves the current kubectl context and other clusters
alone. It generates unique passwords, creates two teams' namespaces, registers
`/acs`, and runs end-to-end checks. It can be rerun after an interrupted install.

| Service | Local URL |
| --- | --- |
| Mattermost | http://localhost:18065 |
| Protected CVE search | http://localhost:18080 |
| Dex test login | http://localhost:15556/dex |
| StackRox UI | https://localhost:18443 |

All published ports bind to loopback. HTTP and non-secure cookies are a deliberate
localhost-only lab configuration. Enterprise settings require HTTPS and secure
cookies. The StackRox UI initially uses a local certificate; the application
trusts the specific StackRox CA rather than disabling certificate verification.

Passwords are in `.local/credentials.json`, which is excluded from Git and created
with owner-only permissions. `alice` and `bob` are Mattermost usernames;
`alice@demo.local` and `bob@demo.local` are their Dex login names. Each person's
Mattermost and Dex password is the same in this demo. `labadmin` administers
Mattermost, and `admin` administers StackRox. Their passwords are separate.

Open **DevSecOps Lab → Team Security**, the private channel shared by Alice and
Bob, and type:

```text
/cve status
/cve scan
/cve CVE-2022-40897
```

Use the actual CVE recorded in `.local/verification.json` for a verified positive
example. Findings change with the vulnerability feed. The slash command returns
a private, expiring login link. Sign in with the same person's Dex account to
view results and publish a regular channel message for the audience. The demo channel uses an explicitly approved `requester` sharing policy: Alice
queries `demo-team-a` and `demo-shared`; Bob queries `demo-team-b` and `demo-shared`.
All channel members can read the resulting ACS post and attached JSON scan
report, including findings from the requester's individual namespace. Each caller
still cannot query the other caller's namespace. The owner-only browser report
expires after four hours; the shared post/file follows Mattermost retention.

Commands in **Town Square** and other unapproved channels return private,
ephemeral results, scoped to the caller. For example, Alice can run
`/acs CVE-2022-40897 demo-team-a` there. In Team Security, Alice may share her authorized findings because that channel
is explicitly approved as the disclosure boundary. An Alice request for
`demo-team-b` is denied in either channel.

The deliberately old sample images provide real vulnerability findings. The
Python sample sleeps; the Java sample runs its application on pod loopback with
no Service or port forwarding. NetworkPolicy blocks sample ingress and egress.
These are isolated lab targets, not production application images.

## Commands

- `/cve status`: reads Central's definitions timestamp for the configured scanner.
  A timestamp older than `database_max_age_hours` (default 24) is stale; missing,
  invalid, future or inaccessible timestamps are unknown. It does not claim every
  new CVE has arrived or that every image has been rescanned.
- `/cve scan [namespace]`: uses Sensor's active-pod inventory for the caller's
  authorized namespaces inside the channel allowlist. Deduplicates runtime image
  digests, includes known init-container images, and calls `/v1/images/scan` with
  `force: true`. A single background worker checks permissions before each image
  and before publishing. Results include supported OS/language package findings,
  scan timestamps, failures, coverage and the current database status. Shared
  results include a JSON attachment readable by the channel. One job at a time,
  at most 100 unique images / 2,000 active pods, 30 minutes, 20,000 finding rows;
  exceeding limits is explicitly rejected or marked incomplete. No missing scan
  is silently replaced by old findings. Restarted jobs are marked interrupted.
- `/cve CVE-YYYY-NNNN [namespace]`: searches existing image scan results for that
  CVE, without forcing a new scan.

- `/cve schedule`: first-time setup and later changes to days, local times,
  timezone, automatic scans/reports, scope and enabled state. See
  [automatic team scans](docs/SCHEDULING.md) for operating limits and credentials.

A private login link connects each command to the requester's verified account.
Inventory is a Sensor snapshot, not a guarantee that every Kubernetes object has
already been ingested. Supported Java/JAR and other language packages are
included when identified by the configured scanner; arbitrary source code,
external dependencies and unsupported package formats are outside this scan.

## Operation

```bash
python3 scripts/platform.py status
python3 scripts/platform.py stop
python3 scripts/platform.py start
python3 scripts/verify.py
python3 -m unittest discover -s tests -v
```

Stopping preserves lab data. A full reinstall can use a new checkout and an
explicitly managed new cluster name after adapting the configuration; do not
delete unrelated Docker volumes or prune system images to fix this project.
The managed cluster is named `cvebridge`, and the Kubernetes namespaces are
`cvebridge`, `stackrox`, `demo-team-a`, `demo-team-b`, and `demo-shared`.

Inspect logs without reading secret objects:

```bash
kubectl --kubeconfig .local/kubeconfig -n cvebridge logs deploy/cvebridge -c app
kubectl --kubeconfig .local/kubeconfig -n cvebridge logs deploy/cvebridge -c proxy
kubectl --kubeconfig .local/kubeconfig -n stackrox get pods
kubectl --kubeconfig .local/kubeconfig -n stackrox logs deploy/scanner
```

## How identity and authorization work

Schedule configuration uses Mattermost-authenticated native dialogs and live
username-based Kubernetes checks; see [native dialog identity](docs/SCHEDULING.md#identity-and-roles-for-native-dialogs).
The following browser login flow applies to manual scans and CVE lookups.

1. Mattermost sends a command authenticated by its command token.
2. The app fetches the caller's account from Mattermost's API and maps its stable
   user ID to an administrator-approved OIDC email. The local installer creates
   this mapping automatically for the demo users. A verified API email can also
   be used when the API exposes its verification flag. An unverified profile
   email is rejected.
   The app does **not**
   trust the command's `user_name`, a submitted email, or browser headers sent
   to the public webhook listener.
3. A random request link is stored for ten minutes and bound to the account's
   identity. The response URL's origin and path are validated against Mattermost.
4. OAuth2 Proxy authenticates the browser with the local Dex provider using
   OIDC authorization code flow with PKCE. The app's browser listener binds
   only to `127.0.0.1` **inside the
   proxy's pod**; it has no Service or external port. Only the proxy can forward
   browser identity to that listener.
5. The app requires the verified login to match the command's account. It asks
   Kubernetes for a `SubjectAccessReview` for that user and their trusted groups,
   specifically `list` on `apps/deployments` in each namespace. The app's own
   service account may list namespaces and create reviews, but cannot read all
   deployments or impersonate users.
6. StackRox queries are restricted to the configured **cluster ID and authorized
   namespace**. Returned objects are checked again before image findings are
   shown. Failed permission checks release no results.
7. Unapproved channels receive `ephemeral` results. A channel explicitly listed
   in `mattermost_channel_scopes` must be private and include the integration
   account and caller. Each human member must have a verified identity mapping.
   With the default `common` policy, shared scope is the intersection of caller
   access, the channel allowlist, and every member's live Kubernetes SAR. The
   explicit `requester` policy uses caller access intersected with the allowlist;
   channel membership authorizes reading those published findings. The local
   Team Security example uses `requester` as requested for this demo.
   Audience and permissions are checked again after lookup, before posting
   a regular post through the REST API authenticated as the dedicated ACS bot.
   The initial owner-bound login link always remains private, and private
   lookups still use ephemeral command callbacks.

Shared posts become channel history: later invitees can read them, and revoking
RBAC blocks new lookups without erasing prior posts. Channel membership and
history retention must therefore follow the organization's data access policy.
The local Team Edition does not enforce directory-based membership or prevent
members from inviting others. For company deployment, use approved membership
controls, such as [group-managed private channels](https://docs.mattermost.com/administration-guide/onboard/managing-team-channel-membership-using-ad-ldap-sync-groups),
where supported by the deployed Mattermost edition, or keep results private.

In `common` policy, other channel members are checked by Kubernetes username with only the standard
`system:authenticated` group. Their IdP groups are never inferred from chat
membership. Group-only RBAC grants need an authoritative directory integration
before shared mode can support them; the current checks conservatively deny
those grants.

The authorization policy is explicit: permission to list deployments grants
access to their image vulnerability information. An organization must approve
this policy and its identity/group mapping. In the lab, the generated Kubernetes
user grants match the configured demo identities.

No matching CVE is **not** proof of a clean environment. The UI reports missing
scans, and coverage depends on image availability, scanner feeds, supported
operating systems, and StackRox ingestion. This lab disables runtime Collector;
it demonstrates workload inventory and image vulnerabilities, not runtime threat
detection. Scanner V4 is disabled in the small lab; the pinned StackRox chart's
legacy scanner is used. A local Helm post-renderer persists its vulnerability
database and gives the initial SQL index build 1 GiB of maintenance memory.
Its disposable scanner index uses a memory-backed volume capped at 3 GiB; the
scanner container has a 4 GiB memory limit, including that volume. This avoids
slow startup from small cache writes on the lab host's disk. This overlay is
only for the bundled local lab, not an organization's existing ACS installation.
An incomplete first import is rebuilt from the upstream dump on retry. The
cluster reserves 2 GiB of free disk to avoid exhausting the host filesystem.

## Upstream references

- [StackRox source and installation](https://github.com/stackrox/stackrox)
- [StackRox published Helm charts](https://github.com/stackrox/helm-charts)
- [Kubernetes authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/)
- [Dex](https://dexidp.io/docs/)
- [Mattermost custom slash commands](https://developers.mattermost.com/integrate/slash-commands/custom/)

Version pins are in `config/versions.json`. StackRox chart downloads are checked
against the digest in the official chart repository index.

## License

MIT for this integration. Upstream components retain their own licenses.
