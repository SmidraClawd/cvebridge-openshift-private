# Verifiering av Go-porten

Kontrollerat 2026-11-02:

- 39 Go-testfunktioner godkända med race detector, inklusive API-testservrar,
  behörighetskontroller, callback-ägarskap, återanvändningsskydd, revisionskonflikter,
  DST-tider, sparad state, larmbekräftelser och manifestgenerering.
- Standardmanifest med intern Service har verifierats med den byggda imagen och
  det riktiga byggskriptet i två namespaces: intern callback, intern imageadress
  och ingen Route. Ett uttryckligt HTTPS-undantag har också verifierats.
- Korta `.env` expanderas till godkända kanal-/schemamappar och intern
  registry-adress. Push-kommandot testas med simulerade `oc`- och containerkommandon:
  routen hittas automatiskt, namespace kontrolleras före push och inloggning
  använder token på stdin. Saknad route eller namespace stoppar pushen.
- Befintlig PVC: Deployment monterar angivet claim-namn på `/data`. Tester
  verifierar att ingen PV, PVC eller lagrings-Secret genereras eller ändras och
  att ogiltiga namn och motstridiga inställningar nekas. Riktigt hjälpskript och
  ny image verifierade med två claim-namn. Deployment accepterades av labbets
  API med server-side dry-run och labbets befintliga PVC-specifikationer bevarades.
- Nätverkslagring: SMB, UNC och NFS genererar statisk PV/PVC med `Retain`.
  Det riktiga hjälpskriptet och den nya imagen har provats för alla tre samt
  standardlagring. PV/PVC accepterades av lokala labbets API med server-side
  dry-run. Tester verifierar separata lagrings-Secrets, felaktiga indata och
  bevarad SQLite-state med rollback-journal och full synkronisering.
- `go vet ./...` godkänd och containerimage byggd från Go-källkoden.
- 11 kontroller mot det befintliga lokala Kubernetes-labbet med riktig Mattermost
  och ACS/StackRox: vanlig användare kör manuell skanning, CVE-sökning och
  provkörning av sparat schema direkt i Mattermost. Rapportkort och JSON-bilagor
  levereras, nya skanntider verifieras, schema bevaras och befintliga kritiska
  CVE:er orsakar ingen upprepad kanalping.
- Manuell körning och schemakörning är även verifierade efter att bot-ID-fältet
  togs bort; botens identitet verifieras via dess autentiserade Mattermost-profil.
- Den manuella skanningen omfattade en image; schemakörningen två images och
  189 råa fyndrader, med noll misslyckade images.
- En tidigare Go-image verifierades med read-only rotfilsystem under UID 98765
  och därefter UID 98766 mot samma beständiga SQLite-volume. Byggskriptets riktiga render-kommando
  skapar privata manifest med filrättigheter 0600 och rätt image.
- Kubernetes-objekten i den genererade installationen accepterades av labbets
  API med server-side dry-run. OpenShift Route kunde inte testas av detta
  Kubernetes-API och ingår inte i det påståendet.

Detta är ett lokalt labbtest, inte en verifierad installation i företagets
OpenShift-kluster. Nya adresser, certifikat, tokens, registry, lagring, roller och
Mattermost-inställningar behöver fortfarande verifieras där.

Ingen riktig SMB- eller NFS-montering har verifierats. Plattformsteamet behöver
kontrollera drivrutin, nätverk, kontouppgifter, UID/grupp, fillåsning och
synkronisering på den avsedda lagringsservern.
