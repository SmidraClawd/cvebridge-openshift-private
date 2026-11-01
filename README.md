# CVEBridge · privat OpenShift-leverans i Go

Beställ ACS/StackRox-skanningar, sök CVE:er och ställ in rapporttider direkt i
Mattermost. Boten visar korta svenska rapportkort med prioriterade fynd,
**Åtgärd** och en fullständig JSON-bilaga. Ingen separat webbapp, Dex eller
OAuth-proxy behövs i Go-versionen.

## Börja med installationen

Följ [den privata installationsguiden](PRIVAT_INSTALLATION.md) och
[steg-för-steg-guiden](START_HAR.md). Fyll i `.env`, bygg och pusha din image,
och applicera filerna i ditt avsedda labbnamespace. Skärmbilderna finns under
`assets/`, inklusive Mattermost-formuläret och rapportkorten.

[Exempel på .env och var du hämtar varje värde](docs/ENV_VARDEN.md) visar konkreta
adresser, ID:n, kontomappning och stegen för att skapa Mattermost- och ACS-tokens.

## Bygg projektet

```sh
go test -race ./...
go vet ./...
docker build -t cvebridge:go .
docker run --rm cvebridge:go version
```

Runtime och konfigurationsgenerator är skrivna i Go. `.env.example` innehåller
12 företagsvärden att fylla i; installationsnamespace är förvalt till `cvebridge`.
Imageadress, tagg, bot-ID och upprepade schemamappar räknas ut automatiskt.
Valfria undantag finns i `.env.advanced.example`.
Riktiga företagsvärden ligger i en privat `.env` och skickas till imagen vid
körning genom Kubernetes-konfiguration. Imagebygget kopierar endast Go-källkod
och modulernas låsfiler.

Följ [utvecklarstarten](START_HAR.md) för koden. Den detaljerade guiden för
företagets OpenShift-installation finns i det här privata repot.

## Använd i Mattermost

| Skriv i godkänd privat teamkanal | Resultat |
| --- | --- |
| `/cve help` | Kommandon och hjälp, privat svar. |
| `/cve scan my-team` | Begär nya imageskanningar och publicerar rapporten i kanalen. |
| `/cve report my-team` | Rapporterar befintligt skanningsunderlag utan ny skanning. |
| `/cve CVE-2021-44228 my-team` | Söker en CVE i images som används av aktiva poddar. |
| `/cve status` | Rapporterar CVE-databasens verkliga aktualitet. |
| `/cve schedule` | Öppnar Mattermost-formuläret för dagar, tider, namespaces och åtgärd. |

Utelämna namespace för att använda hela beställningens tillåtna omfattning.
En manuell beställning ändrar inte schemat. Aliaset `/acs` kräver ett eget
registrerat slash-kommando och dess token i `MATTERMOST_ACS_COMMAND_TOKEN`.

Formuläret öppnas som en dialogruta inne i Mattermost. Välj **Spara inställningar**
och **Utför** för att aktivera. Öppna igen för **Pausa**, **Provkör sparat schema**
eller **Visa körhistorik**. Provkörning använder det senast sparade schemat.
Vanliga användare behöver ingen Mattermost-adminroll. Den första konfigurationen
av botkonto, slash-kommando och kanalåtkomst görs av integrationsansvarig.

Bilderna nedan är från projektets tidigare, riktiga Mattermost-labb. Go-porten
använder samma dialogfält och rapportprincip; bilderna är referensbilder,
inte bevis på en genomförd företagsinstallation.

![Schemaformuläret inne i Mattermost](assets/native-schedule/01-schema-i-mattermost.jpg)

![Åtgärder i Mattermost-formuläret](assets/native-schedule/02-atgarder-i-formularet.jpg)

![Rapport med åtgärd och JSON-bilaga](assets/reports/04-skanningsrapport.jpg)

## Åtkomst och drift

- Ett Mattermost-botkonto utan administratörsroll och en godkänd **privat** kanal.
- Botens ID verifieras med dess token via Mattermost `/users/me`; kontot ska vara
  en bot utan administratörsroll. Stabila Mattermost-användar-ID:n kopplas uttryckligen till exakta klusterkonton
  i `MATTERMOST_KUBE_USER_MAP`. Redigerbara profilnamn och e-postadresser används inte.
- Kubernetes SubjectAccessReview kontrollerar `list deployments` före arbetet,
  under skanningen och före leverans. Endast `system:authenticated` antas för
  människor; gruppbaserad åtkomst måste kompletteras med godkända direkta
  användarbindningar. Boten gissar inga AD-grupper.
- `common` delar bara namespaces som alla kanalmedlemmar har verifierad åtkomst till.
  `requester` är ett uttryckligt godkännande att dela beställarens tillåtna fynd
  med hela kanalen. Kanalhistorik finns kvar även när medlemmar byts.
- Schemalagda körningar använder en separat rapporttjänstidentitet och en
  särskild StackRox-token. Alla kanalmedlemmars identiteter kontrolleras även då.
- CVE-bevakningen sparas på en PVC. Första kompletta rapporten skapar normalt
  ett utgångsläge utan ping. En ny CVE över larmgränsen kan sedan ge `@channel`.
  Ett felaktigt eller ofullständigt underlag visas som luckor, aldrig som rent.
- Kör **en replika**, `Recreate`, med beständig SQLite-databas. Detta är inte en
  HA-installation. Säkerhetskopiera PVC:n. En krasch mellan bekräftat Mattermost-inlägg
  och sparad SQLite-transaktion kan ge ett upprepat larm; exakt-en-gång-leverans garanteras inte.

Botens `/healthz` visar att processen är igång. Det bevisar inte att ACS,
Mattermost och RBAC fungerar; kontrollera en verklig skanning efter installation.

## Varför Deployment och inte operator?

En Deployment räcker för en botinstallation med image, konfiguration, Secret,
Service, Route och PVC. En operator blir relevant när ni vill hantera många
installationer med en egen resurs, till exempel `CVEBridge`, och automatisera
uppgraderingar och återställning. Ingen operator eller CRD ingår i den här versionen.

## Utveckla och testa

```sh
go test -race ./...
go vet ./...
go build ./cmd/cvebridge
```

Go 1.27.3 används av containerbygget och CI. Runtime är en statisk Go-binär i
`scratch`, med CA-certifikat och inbyggda tidszoner. Python krävs inte för bygge,
installation eller botens körning. Den tidigare implementationen och dess
labbverktyg ligger under `legacy/python/` som historisk referens; använd inte
deras installationskommandon för Go-versionen.

Se [arkitektur](docs/ARKITEKTUR.md). OpenShift-installationen måste
verifieras i ert labb med era riktiga adresser, tokens, roller och image-registry.
