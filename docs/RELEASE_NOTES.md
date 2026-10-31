# Första publika projektversionen

Publiceringsunderlag för det lokala CVE Bridge-labbet, förberett 31 oktober 2026.
Källkoden publiceras som ett Git-repo. Någon separat versionsmärkt GitHub-release
har inte skapats.

## Det som ingår

- Repeterbar lokal installation av Mattermost, Dex, Kubernetes RBAC och StackRox.
- `/cve` och `/acs`: hjälp, databasstatus, manuell skanning, CVE-sökning och teamschema.
- Kompakta svenska rapportkort med högst tre prioriterade CVE:er, åtgärder, omfattning och riskfördelning.
- Fullständig JSON-rapport för de rapporterade fynden.
- Schemalagda skanningar eller rapporter med val av namespace, veckodagar, tider och tidszon.
- Beständig historik som begränsar `@channel` till nya CVE:er över larmgränsen. Första fullständiga rapporten skapar normalt ett utgångsläge utan ping.
- README med verkliga skärmbilder och en svensk text som underlag för LinkedIn.

## Verifierat lokalt

- 90 enhetstester för bland annat autentisering, behörigheter, rapportering, scheman och engångslarm.
- Verifierade kommandofel visas som svenska kort i Mattermost; felaktiga integrationstoken avvisas fortfarande.
- 22 flödeskontroller mot den verkliga lokala installationen.
- Manuell skanning av två containerbilder med leverans till Mattermost och JSON-bilaga.
- Tidsstyrd körning, Java/Log4j-fynd, schemaändring och paus har provats i labbet.
- Resursgenerering för anpassade installationer har kontrollerats utan att ändra ett externt kluster.

## Avgränsningar

Detta är ett lokalt demonstrationsprojekt, med en appreplik och utan löfte om
produktionsberedskap. Bildernas skannerdata var markerad som gammal vid
verifieringen. Fixversioner i skärmbilder är skannerns dåvarande underlag.
Inga lösenord, API-token, kubeconfig-filer eller beständiga labbdata ingår.
