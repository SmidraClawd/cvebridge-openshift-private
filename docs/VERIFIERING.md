# Verifiering av Go-porten

Kontrollerat 2026-11-01:

- 20 Go-testfunktioner godkända med race detector, inklusive API-testservrar,
  behörighetskontroller, callback-ägarskap, återanvändningsskydd, revisionskonflikter,
  DST-tider, sparad state, larmbekräftelser och manifestgenerering.
- `go vet ./...` godkänd och containerimage byggd från Go-källkoden.
- 11 kontroller mot det befintliga lokala Kubernetes-labbet med riktig Mattermost
  och ACS/StackRox: vanlig användare kör manuell skanning, CVE-sökning och
  provkörning av sparat schema direkt i Mattermost. Rapportkort och JSON-bilagor
  levereras, nya skanntider verifieras, schema bevaras och befintliga kritiska
  CVE:er orsakar ingen upprepad kanalping.
- Den manuella skanningen omfattade en image; schemakörningen två images och
  189 råa fyndrader, med noll misslyckade images.
- Slutimagen startar med read-only rotfilsystem under UID 98765 och därefter
  UID 98766 mot samma beständiga SQLite-volume. Byggskriptets riktiga render-kommando
  skapar privata manifest med filrättigheter 0600 och rätt image.
- Kubernetes-objekten i den genererade installationen accepterades av labbets
  API med server-side dry-run. OpenShift Route kunde inte testas av detta
  Kubernetes-API och ingår inte i det påståendet.

Detta är ett lokalt labbtest, inte en verifierad installation i företagets
OpenShift-kluster. Nya adresser, certifikat, tokens, registry, lagring, roller och
Mattermost-inställningar behöver fortfarande verifieras där.
