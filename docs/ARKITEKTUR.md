# Arkitektur

En Go-process tar emot autentiserade Mattermost-kommandon och kortlivade
formulär-callbacks. Det finns ingen separat webbapp. Status, CVE-sökning,
manuell skanning och scheman används från en godkänd privat teamkanal.

Stabila Mattermost-ID:n kopplas uttryckligen till klusterkonton. Kubernetes
SubjectAccessReview kontrollerar list-behörighet till deployments per namespace.
Scope och kanalmedlemmar kontrolleras på nytt under körningen och före publicering.
Mänskliga användares grupper gissas inte. Schemalagda körningar har separat
rapporteridentitet och ACS-token.

Sensor levererar inventeringen av aktiva poddar. Runtime-digests binder begärda
skanningar till rätt image; nyliga scan-tidsstämplar verifieras. CVE-sökning och
rapportläge läser befintliga scans. Inaktiva deployment-images ingår inte.
Rapporter begränsas till 100 images, 2 000 poddar, 20 000 rader och 8 MiB bilaga.

SQLite lagrar scheman, revisioner, historik och bekräftade CVE:er på beständig
lagring. En worker och en replika används. Missade schematider spelas inte upp
som en backlogg. Sommartid hoppar över saknade tider och väljer första förekomsten
när klockan ställs tillbaka.

CVE-bevakning uppdateras efter Mattermost-bekräftelse. En krasch mellan inlägget
och SQLite-commit kan ge dubbelleverans; exakt-en-gång-leverans garanteras inte.
Första kompletta rapporten skapar normalt ett utgångsläge utan kanalping.

Containerimagen innehåller en statisk Go-binär, CA-certifikat och tidszoner.
Företagets tokens och adresser byggs inte in. En vanlig Kubernetes Deployment
används; någon operator eller CRD ingår inte.
