# Arkitektur

CVEBridge är en Go-tjänst som kopplar Mattermost till ACS Central och klustrets
Kubernetes-API.

## Tre anslutningar

| Anslutning | Uppgift |
| --- | --- |
| Mattermost ↔ CVEBridge | Slash-kommandon, formulär, rapportkort och JSON-bilagor. |
| CVEBridge ↔ ACS Central | Inventering, skanningsbeställningar, sårbarhetsfynd och databasstatus. |
| CVEBridge → Kubernetes-API | Namespace-behörigheter via SubjectAccessReview. |

Klustrets Sensor rapporterar inventering och aktivitet till Central. Boten
anropar Centrals API. Central kan finnas i samma kluster eller ett annat;
använd en nåbar Central-adress. En `.svc`-adress hör till klustrets tjänstenät.

## Från beställning till rapport

1. Verifiera kommandot, beställaren och den godkända privata kanalen.
2. Kontrollera namespace-behörigheter och kanalens delningspolicy.
3. Läs aktiva poddars images från Central och beställ nya skanningar vid behov.
4. Kontrollera åtkomsten igen och publicera rapporten med Åtgärd och JSON-resultat.

Runtime-digests binder nya skanningar till de images som används. CVE-sökning och
rapportläge läser befintliga skanningsresultat. Beställningar begränsas till 100
unika images, 2 000 aktiva poddar, 20 000 rader och en bilaga på högst 8 MiB.

## Deployment och state

Imagen innehåller en statisk Go-binär, CA-certifikat och tidszoner.
Företagskonfiguration tillförs vid körning via Kubernetes-konfiguration och Secrets.
En vanlig Deployment kör en worker och använder SQLite på PVC. Generatorn skapar
en intern Service som standard; extern HTTPS-route kan väljas uttryckligen.

Lagringen använder klustrets standard-StorageClass om `STATE_NETWORK_URL` är tomt.
Med en SMB- eller NFS-sökväg skapas i stället en statisk PV i bootstrap-filen och
en PVC som binds till just den volymen. Databasen finns alltid på
`/data/requests.sqlite3`. SMB kräver `smb.csi.k8s.io` och en lagrings-Secret;
anslutningsuppgifterna tillförs aldrig botens container. PV:n använder `Retain`.
Filservern behöver verifierad fillåsning, synkronisering och skrivrättigheter för
podens UID/grupp. SQLite använder rollback-journal och full synkronisering,
med en enda botreplika. Enbart en nätverkssökväg garanterar inte fungerande lagring.

SQLite sparar scheman, historik, kortlivade formulär och bekräftade CVE:er.
Missade schematider spelas inte upp som en backlogg. Larm sparas efter att
Mattermost bekräftat inlägget. En krasch mellan publicering och lagring kan ge
ett upprepat larm; exakt-en-gång-leverans garanteras inte.

Se [åtkomstmodellen](ACCESS.md) och [verifieringen](VERIFIERING.md).
