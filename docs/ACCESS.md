# Åtkomstmodell

CVEBridge använder befintliga identiteter och behörigheter. Boten ger inte
teammedlemmar nya klusterbehörigheter.

- Använd ett Mattermost-botkonto utan adminroll i en godkänd privat kanal.
  Den autentiserade botidentiteten verifieras via Mattermosts `/users/me`-API.
- Koppla stabila Mattermost-ID:n till exakta Kubernetes-användarnamn. Profilnamn
  och e-postadresser används inte som implicit identitet.
- Kubernetes SubjectAccessReview kontrollerar `list deployments` per namespace
  före arbete, under skanning och före leverans. Mänskliga användares grupper
  gissas inte; endast `system:authenticated` antas. Gruppbaserad åtkomst kan
  behöva kompletteras med godkända direkta användarbindningar.
- Standardpolicyn `common` delar bara namespaces som alla kanalmedlemmar har
  verifierad åtkomst till. Den valfria policyn `requester` godkänner uttryckligen
  delning av beställarens tillåtna fynd med kanalen. Befintlig kanalhistorik
  ligger kvar när medlemskap ändras.
- Schemalagda körningar använder ett separat reporter-servicekonto och en
  särskild ACS-token. Kanalmedlemskap och identiteter kontrolleras även då.
- Formulärsvar är bundna till ägare och kanal, går ut och kan inte återanvändas.

Separata ACS-token skiljer inventeringsläsning, skanningsbeställningar,
databasstatus och schemakörningar åt. Scope och plattformsbehörigheter godkänns
för respektive installation.

Ofullständig skanning eller gammal CVE-databas visas som luckor. Första kompletta
rapporten skapar normalt ett utgångsläge utan kanalping. Beständig bevakning
minskar upprepade larm men garanterar inte exakt-en-gång-leverans vid krascher.

Kör en replika med beständig SQLite-lagring. `/healthz` är ett processtest;
verifiera en riktig skanning efter anslutning till Mattermost, ACS och Kubernetes.
