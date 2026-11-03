# Driftbevakning av CVE-databasen

Boten läser när ACS Scanners sårbarhetsdatabas senast uppdaterades.
Kontrollen beställer ingen imageskanning och ändrar inga ACS-inställningar.

## Aktivera med ett fält

1. Öppna en **privat driftkanal** i Mattermost.
2. Klicka **Visa info / View Info** via informationsikonen (i).
3. Kopiera **ID** längst ner i panelen. Det är 26 tecken.
4. Bjud in boten till kanalen och lägg ID:t i din lokala `.env`:

```dotenv
DATABASE_MONITOR_CHANNEL_ID=CHANGE_ME_DRIFT_CHANNEL_ID
```

Byt ut exempelvärdet mot kanalens riktiga 26-teckens-ID. Rapportkanalen kan
användas om ni vill ha driftstatus där. Inga nya token behövs; ACS-tokenens
roll behöver redan **Administration: Read** för `/cve status`.

Bygg och uppdatera enligt [README](../README.md). Om den nya programversionen
redan körs och du enbart ändrar `.env`:

```sh
oc project DITT_NAMESPACE
oc create secret generic cvebridge-integration --from-env-file=.env --dry-run=client -o yaml | oc apply --server-side --field-manager=cvebridge-env -f -
oc rollout restart deployment/cvebridge -n DITT_NAMESPACE
```

Den första kontrollen skickas när boten startar. Sedan sker en kontroll per
timme. Ta bort fältet och uppdatera konfigurationen på samma sätt för att stänga av.

## Det driftteamet får

| Läge | Meddelande i Mattermost |
| --- | --- |
| Databasen är högst 24 timmar gammal | Grön status med senaste uppdateringstid och ålder. |
| Databasen är äldre än 24 timmar | Röd varning och Åtgärd: kontrollera definitionshämtning och Scanner-uppdatering. |
| ACS svarar inte eller tiden saknas | Varning om att status inte kan verifieras, med nästa felsökningssteg. |
| Status blir bra igen | Ett återställningsbesked. |

Status skickas direkt första gången och vid ändrat läge, därefter var 24:e
timme så länge läget är samma. Fel upptäcks vid nästa timkontroll. Meddelandena
innehåller **Senast uppdaterad, Ålder, Kontrollerad och Åtgärd**. Ingen
`@channel`-ping görs av denna bevakning.

Senast bekräftade leverans sparas i botens SQLite-databas på er PVC. Därför
kommer inte samma meddelande igen bara för att poden startas om. Misslyckad
leverans försöks igen efter cirka fem minuter. Ett avbrott precis mellan en
lyckad Mattermost-leverans och sparandet kan ge en enstaka dubblett.

## Vad kontrollen visar

Standard är `SCANNER_V4`: boten frågar ACS Central, som hämtar matcherns senaste
sårbarhetsuppdatering. För äldre Scanner kan
`STACKROX_SCANNER_COMPONENT=SCANNER` anges. Åldersgränsen kan vid behov ändras
med `DATABASE_MAX_AGE_HOURS=24`.

Detta är databasstatus för den Scanner-integration som Central returnerar för
vald komponent. Det är ingen kontroll av varje separat Scanner i alla säkrade
kluster, av Scanner-programmets version eller av att varje nypublicerad CVE
redan finns med. En färsk tidsstämpel betyder att databasen är inom er gräns.

Driftkanalen får enbart denna övergripande databasstatus. Att ange den här ger
inte åtkomst till namespace-rapporter eller slash-kommandon. Boten verifierar
att kanalen är privat och aktiv och att botkontot är medlem före leverans.
Kontrollen behöver ingen användarmappning för driftkanalens medlemmar.

Om själva boten eller Mattermost ligger nere kan inget meddelande levereras.
Använd klustrets vanliga övervakning för botens tillgänglighet; `/healthz`
visar endast att botprocessen svarar. Boten uppdaterar inte ACS-databasen åt er.

API och betydelse: [ACS definitionsstatus](https://github.com/stackrox/stackrox/blob/master/proto/api/v1/integration_health_service.proto),
[Scanner V4 matcherns uppdateringstid](https://github.com/stackrox/stackrox/blob/master/pkg/scanners/scannerv4/scannerv4.go#L221-L237),
[behörigheten Administration](https://github.com/stackrox/stackrox/blob/master/central/integrationhealth/service/service_impl.go#L25-L27).
