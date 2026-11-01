# Testa CVE Bridge på datorn

Den fullständiga [utvecklarguiden med riktiga skärmbilder](README.md#manuell-skanning)
visar manuell skanning, specifik CVE-sökning och automatiska körningar steg för steg.

Öppna **http://localhost:18065** och logga in i Mattermost som `alice`.
Det unika lösenordet finns under `alice` i `.local/credentials.json`.

**Alice och Bob är utvecklare. ACS är boten**, med ett eget botkonto och en
sköldikon. Kör `/acs help` för instruktioner. `/cve` fungerar också som alias.

1. Öppna teamet **DevSecOps Lab** och den privata kanalen **Team Security**.
2. Testa de tre kommandona:

   ```text
   /cve status
   /cve scan
   /cve CVE-2022-40897
   ```

3. Klicka på den privata länken efter varje kommando.
4. Logga in som `alice@demo.local`, med samma lösenord som Alice i Mattermost.
5. `status` visar databasens verkliga uppdateringsdatum. `scan` startar nya
   imageskanningar i bakgrunden och visar en sida som uppdateras automatiskt.
   CVE-kommandot söker befintliga fynd för just den CVE:n.
6. ACS publicerar resultatet i kanalen. Vid skanning bifogas en JSON-rapport
   med samtliga rapporterade fynd, läsbar av kanalmedlemmarna.

Alice väljer `demo-team-a` och `demo-shared`; Bob väljer `demo-team-b` och
`demo-shared`. Kanalen är uttryckligen godkänd för att dela beställarens fynd
med alla medlemmar. Ingen av dem kan beställa skanning av den andras namespace.
Inloggningslänken är privat och bunden till beställaren.

ACS visar ett kort med fynd, risknivå, namespace, skanningsunderlag och vilka
paketversioner som åtgärdar fyndet. Gruppsvarets faktiska avsändare är ACS.

Logga in som `bob` i ett annat webbläsarfönster och öppna **Team Security** för
att se samma publicerade resultat. Bob behöver inte öppna Alices inloggningslänk.
Använd gärna ett privat webbläsarfönster när du byter person, så att gamla
inloggningssessioner inte blandas ihop.

**Privata sökningar:** I **Town Square** skickas resultatet bara till den som
kör kommandot. Alice har åtkomst till `demo-team-a` och `demo-shared`; Bob till
`demo-team-b` och `demo-shared`.

För att testa en nekad förfrågan som Alice i Town Square:

```text
/acs CVE-2022-40897 demo-team-b
```

Du ska få nekad åtkomst efter inloggning. Ett annat användarnamn i ett formulär
eller en kopierad länk från Bob ska inte ge åtkomst till hans resultat.

I **Team Security** får Alice dela fynd från `demo-team-a`, eftersom kanalen
använder den godkända delningspolicyn `requester`. `/cve scan demo-team-b`
ska däremot nekas för Alice. Boten kontrollerar beställarens behörigheter och
kanalmedlemmarna igen innan publicering.

Ett delat inlägg ligger kvar i kanalhistoriken. Den som senare bjuds in till
kanalen kan läsa historiken. I en företagsmiljö måste kanalmedlemskapet därför
styras enligt samma åtkomstpolicy som de namespaces vars fynd delas. Den lokala
Team Edition-demon har ingen automatisk AD/LDAP-synkronisering.

**När ett team vill ha ACS:** skapa deras privata kanal och koppla den till
teamets godkända namespaces. Samma bot kan betjäna flera kanaler. Se
[teamanslutning](docs/TEAM_ONBOARDING.md) och `scripts/onboard.py`; verktyget
kontrollerar åtkomsten och ger inga nya Kubernetes-behörigheter.

En befintlig privat teamkanal går också bra. Plattformsteamet godkänner
omfattning och delning, kontrollerar identiteter och åtkomst, lägger till boten
och aktiverar möjligheten till schemaläggning för kanalen. Utvecklarna kör sedan
`/cve schedule` och fyller i dialogrutan direkt i Mattermost. Ingen separat
webbsida eller webbinloggning behövs för schemainställningarna.

**Automatiska körningar:** kör `/cve schedule` i Team Security. Välj dagar,
1–4 tider per dag, tidszon och namespaces. Välj **Spara inställningar** och
klicka **Utför** för att aktivera. Samma kommando
öppnar inställningarna igen så att teamet kan ändra eller pausa schemat, eller
provköra det sparade schemat. Rapportjobbet kör sedan utan personlig inloggning.
Datorn och tjänsterna behöver vara igång vid den valda tiden.

**Vad väljer teamet?** Namespaces visas i en lista med flerval. Första gången är alla
tillåtna alternativ valda; ta bort dem som inte ska ingå. Minst ett
namespace måste väljas. Inom valda namespaces omfattas images som används av
aktiva poddar i Sensors inventering, inklusive kända init-container-images.
Hela containerregistret skannas inte, och val av enskilda appar eller images
inom ett namespace finns ännu inte i formuläret. Teamet väljer också mellan
en ny skanning med rapport och en rapport från befintliga skanningsresultat.
Inga automatiska körningar aktiveras före första sparningen.

Java-testappen finns i `demo-team-a/java-sample` och innehåller ett verifierbart
Log4j-fynd, CVE-2021-44228. Testa `/cve scan demo-team-a` eller
`/cve CVE-2021-44228 demo-team-a`. Den körs isolerat och exponerar ingen tjänst.
Se [schemaläggning och Java-test](docs/SCHEDULING.md).

StackRox gör skanningarna. `/cve scan` begär nya skanningar av images i Sensors
inventering av aktiva poddar, inklusive identifierade OS- och språkpaket.
Java/JAR stöds när scannern kan identifiera paketen; det är ingen garanti för
alla beroenden eller källkod. Saknade/misslyckade skanningar visas uttryckligen.
`/cve CVE-…` söker i befintliga skanningsresultat.

Databasstatus visar Centrals rapporterade uppdateringstid. Äldre än 24 timmar
markeras som gammalt; en otillgänglig uppdateringstid markeras som okänd.
En ny imageskanning innebär inte automatiskt att CVE-databasen är ny.

Du kan också söka direkt på **http://localhost:18080**. Då krävs fortfarande
inloggning och Kubernetes-behörigheter.

**StackRox:** https://localhost:18443, användare `admin`, lösenord under `stackrox`
i lösenordsfilen. Webbläsaren kan varna för det lokala certifikatet.

**Mattermost-administration:** användare `labadmin`, lösenord under `admin` i
lösenordsfilen. Administratörskontot används inte för appens normala CVE-frågor.

Starta och stoppa endast det här projektets lokala miljö:

```bash
python3 scripts/platform.py stop
python3 scripts/platform.py start
python3 scripts/platform.py status
```

Kontrollera det riktiga flödet igen:

```bash
python3 scripts/verify.py
```

Resultatet sparas i `.local/verification.json`. Om installationen avbryts kan du
köra `python3 scripts/platform.py up` igen. Om ingen verifieringsrapport finns
har hela flödet ännu inte godkänts; kontrollera `.local/install.log`.

Allt körs på datorn. Internet behövs för nedladdning av containerbilder och
uppdatering av sårbarhetsdatabasen. Dela inte `.local/`, lösenord, API-token eller
kubeconfig när projektet senare publiceras på GitHub.
