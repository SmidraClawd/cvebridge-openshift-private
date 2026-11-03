# Arkitektur

En Go-process tar emot autentiserade Mattermost-kommandon och kortlivade
formulär-callbacks. Det finns ingen separat webbapp. Status, CVE-sökning,
manuell skanning och scheman används från en godkänd privat teamkanal.

Driftläget använder en privat Mattermost-kanal som åtkomstgräns. Medlemmarna
behöver inga OpenShift-konton eller personliga mappningar. Slash-token, den
konfigurerade kanalen och medlemskap verifieras; sedan används ACS direkt.
Boten har ingen Kubernetes-API-klient eller ServiceAccount-token i detta läge.

```text
Privat driftkanal → Go-boten → ACS Central → rapport i samma kanal
```

Sensorn rapporterar klusterdata till ACS Central. Boten hämtar inventeringen av
aktiva poddar via Centrals API. Central kan finnas i samma kluster eller i ett
annat; `STACKROX_URL` ska vara en adress som boten kan nå.
Grundfilen använder en gemensam ACS-token för status, läsning och skanning.

Runtime-digests binder begärda skanningar till rätt image; nyliga scan-tidsstämplar verifieras. CVE-sökning och
rapportläge läser befintliga scans. Inaktiva deployment-images ingår inte.
Rapporter begränsas till 100 images, 2 000 poddar, 20 000 rader och 8 MiB bilaga.

De färdiga YAML-filerna monterar en befintlig PVC i botens namespace. Du anger
PVC-namnet manuellt som `claimName` i Deployment. Ingen PV eller PVC skapas av
manifesten. Databasen finns på `/data/requests.sqlite3`. Plattformen hanterar
nätverksmontering och rättigheter till lagringen. SQLite använder rollback-journal
och full synkronisering, med en enda botreplika. Lagringen behöver fungerande
fillåsning, synkronisering och skrivrättigheter för podens UID/grupp.

SQLite lagrar scheman, revisioner, historik och bekräftade CVE:er på beständig
lagring. En worker och en replika används. Missade schematider spelas inte upp
som en backlogg. Sommartid hoppar över saknade tider och väljer första förekomsten
när klockan ställs tillbaka.

CVE-bevakning uppdateras efter Mattermost-bekräftelse. En krasch mellan inlägget
och SQLite-commit kan ge dubbelleverans; exakt-en-gång-leverans garanteras inte.
Första kompletta rapporten skapar normalt ett utgångsläge utan kanalping.

Containerimagen innehåller en statisk Go-binär med tidszonsdata. CA-paketet
monteras från klustret och ingår inte i imagen.
Företagets tokens och adresser byggs inte in. En vanlig Kubernetes Deployment
används med en intern Service som standard. Se [åtkomstmodellen](ACCESS.md) för
identiteter, delning och behörighetsgränser.

Konfiguration skickas genom `envFrom`: icke-hemliga värden från `cvebridge-config`
och tokenvärden från `cvebridge-tokens`. Namespace hämtas från poddens metadata.
Ingen lokal `.env` eller import av en sådan fil behövs för installationen.
