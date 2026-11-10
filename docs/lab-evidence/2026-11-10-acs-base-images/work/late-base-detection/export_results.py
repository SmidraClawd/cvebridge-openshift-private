import json,pathlib,datetime,hashlib
W=pathlib.Path(__file__).resolve().parent;ROOT=W.parent.parent;O=ROOT/'outputs';O.mkdir(exist_ok=True)
s=json.loads((W/'run.json').read_text());assert s.get('cleanup') and s.get('allAssertionsPassedAt')
native=json.loads((W/'after-https-both-rescan-native-summary.json').read_text())
bundle={'test':s,'nativeBefore':json.loads((W/'native-baseline-native-summary.json').read_text()),'nativeAfterFirstRegistrationBeforeRescan':json.loads((W/'after-https-311-before-rescan-native-summary.json').read_text()),'nativeAfterFirstRescan':json.loads((W/'after-https-311-rescan-native-summary.json').read_text()),'nativeAfterSecondRegistrationBeforeRescan':json.loads((W/'after-https-both-before-rescan-native-summary.json').read_text()),'nativeFinal':native,'watcherLog':(W/'watcher-final.log').read_text()}
ev=O/'acs-aldre-basimages-bevis.json';ev.write_text(json.dumps(bundle,ensure_ascii=False,indent=2))
lines=[
'ACS: äldre basimage registrerad efter att appimagen byggts',
'Testdatum: 2026-11-10. Tider nedan i UTC.',
'Resultat: GODKÄNT, '+str(len(s['assertions']))+' verifieringar.',
'Miljö: verklig lokal Red Hat ACS '+s['acsMetadata']['version']+' (release), Kubernetes-kluster k3d-cvebridge.',
'Test-ID: '+s['runId'],
'',
'Slutsats',
'ACS kunde efter registrering av historiska baser och uttrycklig omskanning identifiera rätt bas för två appimages som byggts, skannats och startats före registreringen. Ingen app byggdes om och apparnas manifest, konfiguration och lager var oförändrade.',
'Detta verifierar igenkänning i efterhand när ACS faktiskt kan hämta och indexera den gamla basens metadata. Det bevisar inte att enbart registrering av ett reponamn automatiskt täcker alla historiska digests, eller att en gammal digest hittas när dess tagg har flyttats och ACS saknar dess metadata.',
'',
'Observerat resultat',
'Bas                       Före registrering  Bara 3.11 registrerad + omskanning  Båda registrerade + omskanning',
'Python 3.10.0-slim (2021)  Ingen träff        Ingen träff (negativ kontroll)      Rätt bas och exakt digest',
'Python 3.11.0-slim (2022)  Ingen träff        Rätt bas och exakt digest           Rätt bas och exakt digest',
'',
'Metod och tidsordning',
'1. Hämtade de officiella historiska Python-baserna för linux/amd64 och byggde två appimages med ett extra COPY-lager. Testade start utan nätverk, som icke-root och med skrivskyddat filsystem.',
'2. Speglade appimages till befintligt lokalt testregister och skannade dem med POST /v1/images/scan, force=true. Båda saknade baseImageInfo.',
'3. Startade exakt samma appdigests i ett separat namespace så att Sensor inventerade dem. GET /v1/images/{digest} bekräftade att båda saknade baseImageInfo även i den vanliga inventeringen.',
'4. Registrerade en separat basreferens registry.hub.docker.com/library/python med taggmönster 3.11.0-slim EFTER appbyggen, skanningar och klusterstart.',
'5. Väntade på att Central-loggen bekräftade lyckad metadatahämtning. Före omskanning var den lagrade appskanningen fortfarande utan basträff. Efter force=true fick endast 3.11-appen en träff.',
'6. Utökade enbart testreferensens taggmönster till 3.1[01].0-slim, vilket i testet inkluderade båda exakta gamla taggarna. Efter lyckad metadatahämtning och omskanning fick också 3.10-appen rätt träff.',
'7. Jämförde manifestdigest, konfigurationsdigest och hela listan lager före/efter, basdigest mot de ursprungliga manifesten, och API-skanningen mot den vanliga klusterinventeringen.',
'',
'Registrering 3.11 begärd: '+s['secureRegistrationRequestedAt'],
'3.11 metadata inläst: 2026-11-10T22:47:50.204227Z (Central-logg).',
'Utökning till båda baserna begärd: '+s['securePatternExpandedAt'],
'3.10 metadata inläst: 2026-11-10T22:48:49.725627Z (Central-logg).',
'',
'Viktiga avgränsningar',
'Appimagesen byggdes under testet, före registreringen. Själva baserna skapades 2021 respektive 2022; detta test simulerar alltså registrering i efterhand med verkliga gamla baslager.',
'Vi provade uttrycklig omskanning. Den korta kontrollen efter indexering uppdaterade inte den redan lagrade appskanningen; testet avgör inte när en eventuell schemalagd omskanning annars hade uppdaterat den.',
'Testet avser igenkänning av basen. Ingen sårbarhet åtgärdades, inga paket uppdaterades och ingen CVE-rapport eller policyfunktion verifierades här.',
'',
'Anslutningsproblem som upptäcktes',
'Första försöket registrerade en separat kopia av 3.11-basen i labbets befintliga HTTP-register. On-demand-skanning av apparna fungerade, men baswatcherns tagglistning försökte HTTPS och misslyckades med "http: server gave HTTP response to HTTPS client". Detta räknades inte som ett lyckat detektionstest.',
'För huvudtestet användes därför Docker Hubs HTTPS-endpoint registry.hub.docker.com med certifikatverifiering. Vi verifierade att de historiska basmanifesten, konfigurationsdigestarna och samtliga baslager där var identiska med dem i de redan byggda appimagesen. Ingen TLS-verifiering stängdes av.',
'K3s-noden kunde inte DNS-resolvera det befintliga testregistrets .svc-namn vid bildhämtning. Samma oförändrade appdigests förladdades via registrets ClusterIP. Ingen DNS- eller registerkonfiguration ändrades.',
'',
'Digestbevis',
]
for c in s['cases']:
 r=next(r for r in s['after-https-both'] if r['minor']==c['minor'])
 lines += [
  'Python '+c['minor'],
  '  Bas skapad: '+c['created'],
  '  Bas tagg: '+c['tag'],
  '  Exakt basmanifest: '+c['mirroredBase']['manifestDigest'],
  '  App byggd färdigt: '+c['appBuildFinished'],
  '  Oförändrat appmanifest: '+c['appManifest']['manifestDigest'],
  '  Oförändrad appkonfiguration: '+c['appManifest']['configDigest'],
  '  Slutlig skanning: '+r['scanTime'],
  '  ACS baseImageInfo: '+json.dumps(r['baseMatches'],ensure_ascii=False),
  '',
 ]
lines += ['Verifieringar']+['GODKÄNT: '+c for c in s['assertions']]+[
'',
'Städning och påverkan',
'Tillfälligt namespace med två testdeployments, båda tillfälliga basreferenserna och den tillfälliga HTTPS-registerintegrationen togs bort. Den port-forward som öppnades för registret stoppades.',
'Den befintliga Python-basreferensen återstår exakt som före testet. Alla ursprungliga deployments behöll UID, generation och imagekonfiguration.',
'Testbildernas blobbar finns kvar i det befintliga testregistret och i lokala bildcacher. Ingen garbage collection gjordes på det delade registret.',
'Städning klar: '+s['cleanup']['at'],
'',
'Maskinläsbart bevis: '+ev.name,
'SHA256 för bevisfilen: '+hashlib.sha256(ev.read_bytes()).hexdigest(),
]
report=O/'acs-aldre-basimages-test.txt';report.write_text('\n'.join(lines)+'\n')
assert 'Resultat: GODKÄNT' in report.read_text()
assert len(json.loads(ev.read_text())['test']['assertions'])==17
print(json.dumps({'report':str(report),'evidence':str(ev),'checks':len(s['assertions']),'cleanup':s['cleanup']},ensure_ascii=False,indent=2))
