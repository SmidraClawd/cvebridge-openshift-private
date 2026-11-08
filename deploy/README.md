Här ligger dina lokalt ifyllda YAML-filer för `oc apply -f deploy/`.
De och deras tokens hålls utanför Git. Du kan redigera ConfigMap och Secret
manuellt eller låta `../configure.sh` generera filerna från sparade skriptsvar.

Saknas Route för din befintliga Service? Kör från projektets rot:

```sh
cp route.yaml deploy/route.yaml
oc apply -f deploy/route.yaml
oc get route cvebridge-webhook -n image-security
```

Mallen använder namespace `image-security` och port `8001`. Byt namespace om
boten ligger i ett annat projekt. Värdnamnet väljs av OpenShift.

Steg 6 i `../README.md` visar varje Mattermost-fält, token i Secret,
formuläradress i ConfigMap och omstart efter manuella inställningsändringar.
Enbart skapandet av Route kräver ingen omstart eller nytt imagebygge.

Skriptet återskapar filer från `.local/setup.json`; det importerar inte dina
manuella YAML-ändringar. Saknas obligatoriska skriptsvar skapas inga installationsfiler.
