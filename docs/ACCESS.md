# Driftkanalen styr åtkomsten

Standardläget i den privata installationen är `ACCESS_MODE: operations`.
Ange en privat driftkanal i `MATTERMOST_CHANNEL_ID` och projekten som ska
skannas i `SCAN_NAMESPACES`. Bjud in boten och driften till kanalen.

Alla medlemmar i driftkanalen kan köra status, skanningar, CVE-sökning och
skapa eller ändra kanalens schema. Nya kollegor behöver bara bjudas in där.
Ingen `MATTERMOST_KUBE_USER_MAP`, personligt OpenShift-konto eller
Kubernetes-behörighetskontroll används. Boten hämtar data direkt från ACS Central.

Slash-token, TLS, den konfigurerade privata kanalen och botens/avsändarens
medlemskap verifieras. Kommandon i andra kanaler och skanning av projekt utanför
`SCAN_NAMESPACES` avvisas. ACS-tokenens roll och access scope avgör vilka
klusterdata boten faktiskt kan hämta och vilka skanningar den kan beställa.

Formulär är bundna till personen och kanalen, går ut och kan inte återanvändas.
Alla driftmedlemmar kan ändra schemat; samtidig redigering skyddas av revisioner.
Schemalagda rapporter fortsätter utan koppling till en tidigare skapares klusterkonto.
Behörigheten att bjuda in personer till driftkanalen styr vilka som får se
kanalens rapporter och historik.

Botens ServiceAccount har ingen API-token monterad och behöver ingen
SubjectAccessReview-, reporter- eller listbehörighet i klustret.
Den tidigare modellen finns kvar i koden för uttryckligt `ACCESS_MODE: per-user`,
men används inte av driftinstallationens YAML-filer.

Scheman och larmstatus sparas på PVC:n. Kör en replika med Recreate.
`/healthz` visar att processen svarar; verifiera en riktig skanning i ert labb.
