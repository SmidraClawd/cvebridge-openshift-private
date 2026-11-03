# Arkitektur

En Go-process tar emot autentiserade Mattermost-kommandon och kortlivade
formulär-callbacks. Det finns ingen separat webbapp. Status, CVE-sökning,
manuell skanning och scheman används från en godkänd privat teamkanal.

Stabila Mattermost-ID:n kopplas uttryckligen till klusterkonton. Kubernetes
SubjectAccessReview kontrollerar list-behörighet till deployments per namespace.
Scope och kanalmedlemmar kontrolleras på nytt under körningen och före publicering.
Mänskliga användares grupper gissas inte. Schemalagda körningar har separat
reporteridentitet i Kubernetes. Grundfilen använder en gemensam ACS-token;
separata token kan anges som valfria undantag.

Sensorn rapporterar klusterdata till ACS Central. Boten hämtar inventeringen av
aktiva poddar via Centrals API och använder labbets Kubernetes-API för
behörighetskontroll. Central kan finnas i samma kluster eller i ett annat;
`STACKROX_URL` ska vara en adress som boten kan nå. Lokala `.svc`-adresser
fungerar inom respektive klusters tjänstenät.

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

Containerimagen innehåller en statisk Go-binär, CA-certifikat och tidszoner.
Företagets tokens och adresser byggs inte in. En vanlig Kubernetes Deployment
används med en intern Service som standard. Se [åtkomstmodellen](ACCESS.md) för
identiteter, delning och behörighetsgränser.
