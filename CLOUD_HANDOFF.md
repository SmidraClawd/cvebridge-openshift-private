# CVEBridge: fortsättning i molnet

Överlämning 2026-11-11. Den här filen är den senaste kontrollpunkten för
basimages. Läs därefter `AI_HANDOFF.md` för produktens kod, konfiguration och
tidigare rättningar.

## Repo och branch

- Repo: <https://github.com/SmidraClawd/cvebridge-openshift-private>
- Branch: `codex/acs-baseimage-cloud-handoff-20261111`
- Utgångspunkt: `2c995a7` på `fix/acs-inventory-and-report-versions`.
- Den nya branchen innehåller också de tidigare kodrättningarna genom
  `2c995a7`; det senaste arbetet tillför testunderlag och överlämning.
- Användaren vill fortsätta i en **ny molnchatt**, utan arbete på sin dator.
  Hämta denna branch i molnets arbetskatalog via befintlig Git-anslutning.

## Vad användaren vill åstadkomma

Fokus är basimages: vilka gamla baser som används, vilka CVE:er som hör till
basen och vilken ny bas som kan minska fynden. Skilj mellan en paketfixversion
som ACS rapporterar och en ny basimage som CVEBridge väljer och separat
verifierar. Påstå inte att ACS rekommenderar en ny basimage-tagg när underlaget
bara anger en fixversion för ett paket.

En ny push av en uppdaterad bas ändrar inte redan byggda appimages. De måste
byggas om och rullas ut för att få de nya lagren. Att identifiera deras gamla
bas i ACS är en separat funktion och krävde ingen ombyggnad i testet nedan.

## Senaste verkliga integrationstestet

Testet kördes 2026-11-10 i ett lokalt labb med verklig **ACS 4.11.6 release**,
Sensor och Scanner, i klustret `k3d-cvebridge`. Det var inte en mock eller en
kontroll av företagets installation.

Två appimages byggdes från historiska officiella Python-baser med ett extra
COPY-lager. De skannades och startades i ett separat namespace innan någon
motsvarande testreferens registrerades under Base Images.

| Bas | Före registrering | Endast 3.11 inkluderad, omskannat | Båda inkluderade, omskannat |
| --- | --- | --- | --- |
| `3.10.0-slim`, bas skapad 2021 | Ingen träff | Ingen träff: negativ kontroll | Rätt bas och exakt digest |
| `3.11.0-slim`, bas skapad 2022 | Ingen träff | Rätt bas och exakt digest | Rätt bas och exakt digest |

Registreringen skedde efter appbyggen, första skanning och klusterstart.
Apparnas manifestdigests, konfigurationsdigests och lager var oförändrade.
Efter att baswatchern läst in metadata gjordes en uttrycklig omskanning med
`POST /v1/images/scan`, `force=true`. Resultaten i `baseImageInfo` bekräftades
också genom `GET /v1/images/{digest}` i den vanliga klusterinventeringen.
Sammanlagt godkändes 17 verifieringar och städningen verifierades.

Detta visar igenkänning i efterhand när ACS kan hämta och indexera rätt gamla
bas. Det visar inte att ett brett taggmönster täcker alla historiska digests,
eller att en gammal digest hittas när taggen skrivits över och dess metadata
saknas i ACS. Testet avgör inte heller när en schemalagd omskanning annars
skulle ha uppdaterat den lagrade appskanningen. Appimagesen byggdes under
testet; de gamla baslagren skapades 2021 respektive 2022.

## Anslutningsproblem och vad som användes

- Första försöket mot det befintliga HTTP-testregistret misslyckades i
  baswatcherns tagglistning: ACS försökte HTTPS och fick
  `http: server gave HTTP response to HTTPS client`. Appskanningen via den
  befintliga integrationen fungerade. Räkna inte detta försök som godkänt.
- Huvudtestet använde därför Docker Hubs verifierade HTTPS-endpoint
  `registry.hub.docker.com/library/python`, först `3.11.0-slim`, sedan
  `3.1[01].0-slim`. Dess basmanifest, konfiguration och samtliga lager
  verifierades som identiska med de redan byggda apparnas baser.
- Noden kunde inte resolvera det lokala registrets `.svc`-namn. Samma
  oförändrade appdigests förladdades via registrets ClusterIP. Ingen DNS-,
  register- eller TLS-förtroendekonfiguration ändrades.
- Testnamespace, två tillfälliga basreferenser, tillfällig HTTPS-integration
  och registrets tillfälliga port-forward togs bort. Den ursprungliga
  Python-registreringen och alla ursprungliga deployments är oförändrade.
  Testblobbar finns kvar i labbets bildcacher/register; ingen gemensam
  garbage collection utfördes.

## Tidigare rapportarbete i samma chatt

Mattermost-testposten ändrades till en tabell över nuvarande bas och en
separat skannad kandidat. Detta var en redigering av en labbpost, inte en
ny implementation av automatisk kandidatväljning i Go-koden.

- Nuvarande: `python:3.13.9-slim`, 4 kritiska och 15 höga paketfynd.
- Kandidat: `python:3.13.18-slim-trixie`, 0 kritiska och 4 höga paketfynd.
- Totalt 56 respektive 33 paketfynd. Kandidaten starttestades på linux/amd64.
- Båda ACS-svaren hade `OS_CVES_UNAVAILABLE` och `PARTIAL_SCAN_DATA`.
  Siffrorna visar det tillgängliga underlaget vid testtillfället, inte en
  fullständig säkerhetsgaranti eller aktuell rekommendation för senare datum.
- Appkompatibilitet och en verklig utrullning av kandidaten verifierades inte.
- Publicera eller redigera inte Mattermost-meddelanden igen utan ny instruktion.

## Filer och verifiering utan lokalt kluster

Allt nytillkommet underlag från den föregående chatmappens `work/` och
`outputs/` finns under:

`docs/lab-evidence/2026-11-10-acs-base-images/`

- `outputs/acs-aldre-basimages-test.txt`: läsbart testprotokoll med digests.
- `outputs/acs-aldre-basimages-bevis.json`: samlad maskinläsbar bevisning.
- `work/late-base-detection/`: ursprungliga testskript, råa ACS-svar,
  registreringar, native inventering, bygglogg och watcherloggar.
- `work/base-image-report/` och `work/mattermost-version-fix/`: tidigare
  rapportunderlag och skanningsjämförelser.
- `outputs/*.jpg`: rapportbilder från labbets Mattermost.

Kör den fristående kontrollen av sparade bevis från repots rot:

```sh
python3 docs/lab-evidence/2026-11-10-acs-base-images/verify_evidence.py
```

Detta läser enbart filer och bekräftar bevisens interna överensstämmelse.
Det gör inget nytt integrationstest. De ursprungliga live-skripten är sparade
som proveniens och har labbspecifika lokala sökvägar och anslutningar. De är
inte färdiga att köra i molnet. Deras lokala API-hjälpare och autentisering
är inte med i Git.

Go-kodens ordinarie kontroller är `go test -mod=vendor -race ./...` och
`go vet -mod=vendor ./...`; CI bygger också Dockerimagen. Go-koden ändrades
inte i denna överlämningscommit. Se aktuell CI-status för körningen efter push.

## Gränser för fortsättningen i molnet

Molnet har inte automatiskt åtkomst till datorns k3d-/kind-kluster, localhost,
port-forwards eller Mattermost. Använd inte lokala verktyg på användarens dator.
Behåll fungerande företagsmanifest, PVC, CA-förtroende och tokens. Inga tokens,
lösenord, kubeconfigs, privata nycklar eller ifyllda företagsmanifest kopierades
till denna överlämning. Begär inte hemligheter i chatten.

Om Git-åtkomst saknas i molnet, beskriv det konkreta åtkomstfelet och vilken
repoanslutning som behövs. Påstå inte att klustret är migrerat eller att
live-tester har körts i molnet utifrån dessa sparade bevis.

Nästa chatt ska först läsa dessa filer, verifiera branch och sparade bevis och
bekräfta att den är redo för användarens nästa ändring. Det finns inget
ytterligare automatiskt godkänt installations- eller utrullningsarbete.
