package bridge

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"unicode"
)

func inert(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r == '@' {
			return '＠'
		}
		if r == '`' {
			return -1
		}
		if r == '|' {
			return '/'
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > limit {
		r = append(r[:limit], '…')
	}
	return "`" + html.EscapeString(string(r)) + "`"
}
func score(r M) float64 {
	v := num(r["cvss"])
	if v >= 0 && v <= 10 {
		return v
	}
	return 0
}
func risk(v float64) (string, string) {
	if v >= 9 {
		return "Kritisk", "#D64550"
	}
	if v >= 7 {
		return "Hög", "#D97732"
	}
	if v >= 4 {
		return "Medel", "#C89431"
	}
	if v > 0 {
		return "Låg", "#438D9A"
	}
	return "Ej bedömd", "#718096"
}
func card(title, text, summary, color string) M {
	return M{"text": summary, "attachments": []any{M{"fallback": title, "title": title, "text": text, "color": color, "footer": "ACS · StackRox"}}}
}
func ErrorMessage(err error) M {
	return card("Förfrågan kunde inte slutföras", message(err), "**ACS · Kontrollera beställningen**", "#D97732")
}
func HelpMessage() M {
	return card("Vad vill du göra?", "`/cve scan [namespace]` – ny skanning och imagetabell.\n`/cve report [namespace]` – imagetabell från befintligt underlag.\n`/cve CVE-2025-47273 [namespace]` – sök en CVE.\n`/cve CVE-2025-47273 CVE-2022-40897 [namespace]` – sök flera, högst 20 olika. Kommatecken fungerar också.\n`/cve search CVE-2025-47273,CVE-2022-40897 [namespace]` – samma sökning med search.\n`/cve schedule` – öppna schemaformuläret här.\n`/cve status` – CVE-databasens aktualitet.\n`/cve sensor` – valt klusters sensorkontakt med Central.\n\nKör i botens konfigurerade privata kanal. Utan namespace används kanalens godkända projekt. CVE-sökning läser befintliga ACS-resultat, utan ny skanning. Tabellerna skickas utan JSON-bilaga.", "**ACS · Snabbhjälp**", "#438D9A")
}
func ResultMessage(r M) M {
	switch str(r["kind"]) {
	case "scan":
		return imageReportMessages(r)[0]
	case "lookup":
		return cveLookupMessages(r)[0]
	case "database_monitor":
		return databaseMonitorMessage(r)
	case "sensor_monitor", "sensor_status":
		return sensorMonitorMessage(r)
	case "status":
		state := str(r["state"])
		title, color := "Databasens aktualitet är okänd", "#718096"
		if state == "recent" {
			title, color = "Databasen är nyligen uppdaterad", "#329C89"
		}
		if state == "stale" {
			title, color = "Databasen behöver uppdateras", "#D97732"
		}
		text := fmt.Sprintf("**Senast uppdaterad:** %s\n**Ålder:** %v timmar · gräns %v timmar\nEn ny imageskanning innebär inte att CVE-databasen har uppdaterats.", inert(str(r["lastUpdated"]), 40), r["ageHours"], r["maxAgeHours"])
		return card(title, text, "**ACS · CVE-databas**", color)
	case "schedule":
		b, _ := jsonSchedule(r["config"])
		title := "Automatiska körningar pausade"
		if boolean(r["enabled"]) {
			title = "Automatiska körningar aktiverade"
		}
		days := []string{}
		for _, d := range b.Days {
			if d >= 0 && d < 7 {
				days = append(days, Days[d][:3])
			}
		}
		return card(title, "**När:** "+strings.Join(days, ", ")+" · "+strings.Join(b.Times, ", ")+" · "+b.Timezone+"\n**Namespace:** "+scope(b.Namespaces)+"\nKör `/cve schedule` för att ändra, provköra eller pausa.", "**ACS · Teamets schema**", "#329C89")
	case "schedule_error":
		return card("Automatisk körning misslyckades", "Leveransen är inte bekräftad. Kör `/cve schedule` och välj körhistorik.", "**ACS · Körningen behöver kontrolleras**", "#D64550")
	}
	rows := arr(r["rows"])
	groups := map[string]M{}
	cves := map[string]bool{}
	highest := 0.0
	for _, v := range rows {
		row := obj(v)
		key := str(row["imageId"]) + "|" + str(row["component"]) + "|" + str(row["version"]) + "|" + str(row["cve"])
		groups[key] = row
		cves[str(row["cve"])] = true
		if score(row) > highest {
			highest = score(row)
		}
	}
	title := "Skanning klar"
	if str(r["mode"]) == "report" {
		title = "Rapport klar"
	}
	if str(r["kind"]) == "lookup" {
		title = "Berörda arbetslaster"
	}
	if boolean(r["scheduled"]) {
		title = "Automatisk · " + strings.ToLower(title)
	}
	if incomplete(r) {
		title += " med luckor"
	}
	_, color := risk(highest)
	details := []string{"**Namespace:** " + scope(stringsOf(r["namespaces"])), fmt.Sprintf("**Täckning:** %v/%v bilder · %v poddar · %v paket", r["scannedImages"], r["totalImages"], r["pods"], r["components"])}
	if _, ok := r["newCves"]; ok {
		line := fmt.Sprintf("**Nytt för kanalen:** %d CVE:er · %d över larmgränsen.", len(stringsOf(r["newCves"])), len(stringsOf(r["alertCves"])))
		if boolean(r["alertBaseline"]) {
			line = "**Bevakning:** första kompletta rapporten skapar ett utgångsläge."
		}
		details = append(details, line)
	}
	ranked := []M{}
	counts := map[string]int{}
	for _, row := range groups {
		ranked = append(ranked, row)
		label, _ := risk(score(row))
		counts[label]++
	}
	riskCounts := []string{}
	for _, label := range []string{"Kritisk", "Hög", "Medel", "Låg", "Ej bedömd"} {
		if counts[label] > 0 {
			riskCounts = append(riskCounts, fmt.Sprintf("%s %d", label, counts[label]))
		}
	}
	if len(riskCounts) > 0 {
		details = append(details, "**Paketfynd per risk:** "+strings.Join(riskCounts, " · "))
	}
	alerts := stringsOf(r["alertCves"])
	sort.Slice(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		ua, ub := has(alerts, str(a["cve"])), has(alerts, str(b["cve"]))
		if ua != ub {
			return ua
		}
		if score(a) != score(b) {
			return score(a) > score(b)
		}
		return str(a["cve"])+str(a["component"]) < str(b["cve"])+str(b["component"])
	})
	shown := map[string]bool{}
	for _, row := range ranked {
		cve := str(row["cve"])
		if shown[cve] {
			continue
		}
		if len(shown) == 3 {
			break
		}
		if len(shown) == 0 {
			details = append(details, "\n**Prioriterade fynd**")
		}
		shown[cve] = true
		version := "Inte angivet av ACS"
		if value := str(row["version"]); strings.TrimSpace(value) != "" {
			version = inert(value, 128)
		}
		fix := "Inte angivet av ACS"
		if value := str(row["fixedBy"]); strings.TrimSpace(value) != "" {
			fix = inert(value, 128)
		}
		label, _ := risk(score(row))
		finding := fmt.Sprintf("• %s · %s · %g/10\n**Paket:** %s\n**Ni har:** %s\n**Rättad i (enligt ACS):** %s", inert(cve, 30), label, score(row), inert(str(row["component"]), 80), version, fix)
		if image := str(row["image"]); image != "" {
			finding += "\n**Image:** " + inert(image, 180)
		}
		details = append(details, finding+"\n")
	}
	if len(rows) > 0 {
		details = append(details, "\n**Åtgärd:** uppdatera berörda paket eller basimages, bygg om och rulla ut. Följ upp med en ny rapport efter nästa ACS-skanning.")
	} else {
		details = append(details, "Inga matchande fynd i tillgängligt underlag. Det bevisar inte att miljön är fri från sårbarheter.")
	}
	if incomplete(r) {
		details = append(details, fmt.Sprintf("⚠ **Luckor:** %v misslyckade · %v saknar underlag · %v med varningar. Se bilagan.", r["failedImages"], r["unscannedImages"], r["partialImages"]))
	}
	db := obj(r["database"])
	if str(db["state"]) != "recent" {
		details = append(details, "⚠ **CVE-databasens aktualitet behöver kontrolleras.**")
	}
	if len(stringsOf(r["reportFileIds"])) > 0 {
		details = append(details, "**Alla fynd och detaljer:** bifogad JSON-rapport.")
	}
	summary := fmt.Sprintf("**%d CVE:er** · %d paketfynd", len(cves), len(groups))
	if str(r["kind"]) == "lookup" {
		summary = "**" + str(r["cve"]) + "** · " + fmt.Sprint(len(rows)) + " fynd"
	}
	if len(alerts) > 0 {
		summary = "@channel **Nya kritiska CVE:er** · " + summary
	}
	return card(title, strings.Join(details, "\n"), summary, color)
}
