package bridge

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

func reportTargets(entry InventoryImage) []any {
	targets := []any{}
	for _, target := range entry.Targets {
		targets = append(targets, M{"namespace": target.Namespace, "image": target.Image})
	}
	return targets
}

// ACS layerIndex and maxLayerIndex count history entries, including empty
// layers. Never substitute zero for an absent index or infer origin from the
// package ecosystem: an application library can already belong to the base.
func historyIndex(value any) (int, bool) {
	switch value.(type) {
	case int, int64, float64:
	default:
		return 0, false
	}
	n := num(value)
	if n < 0 || n > math.MaxInt32 || n != math.Trunc(n) {
		return 0, false
	}
	return int(n), true
}

func matchedBase(image M) M {
	layers := arr(obj(obj(image["metadata"])["v1"])["layers"])
	best := M{}
	boundary := -1
	ambiguous := false
	for _, raw := range arr(image["baseImageInfo"]) {
		base := obj(raw)
		index, ok := historyIndex(base["maxLayerIndex"])
		name, digest := str(base["baseImageFullName"]), str(base["baseImageDigest"])
		if !ok || index >= len(layers) || !Image.MatchString(name) || !Digest.MatchString(digest) {
			continue
		}
		if index > boundary {
			best, boundary, ambiguous = base, index, false
		} else if index == boundary {
			if str(best["baseImageDigest"]) != digest {
				ambiguous = true
			} else if name < str(best["baseImageFullName"]) {
				best = base // Multiple names for the same base digest are aliases.
			}
		}
	}
	if ambiguous {
		return M{}
	}
	return best
}

// Use the severity assigned by ACS rather than recomputing it from CVSS.
func findingCounts(parts []any) M {
	counts := M{"critical": 0, "high": 0, "other": 0, "unknown": 0, "total": 0}
	seen := map[string]bool{}
	for _, raw := range parts {
		part := obj(raw)
		for _, item := range arr(part["vulns"]) {
			vuln := obj(item)
			cve := strings.ToUpper(str(vuln["cve"]))
			key := str(part["name"]) + "\x00" + str(part["version"]) + "\x00" + cve
			if !CVE.MatchString(cve) || seen[key] {
				continue
			}
			seen[key] = true
			category := "unknown"
			switch str(vuln["severity"]) {
			case "CRITICAL_VULNERABILITY_SEVERITY":
				category = "critical"
			case "IMPORTANT_VULNERABILITY_SEVERITY":
				category = "high"
			case "MODERATE_VULNERABILITY_SEVERITY", "LOW_VULNERABILITY_SEVERITY":
				category = "other"
			}
			counts[category] = int(num(counts[category])) + 1
			counts["total"] = int(num(counts["total"])) + 1
		}
	}
	return counts
}

func addImageSummary(summary, image M, partial bool) {
	parts := arr(obj(image["scan"])["components"])
	base := matchedBase(image)
	boundary, matched := historyIndex(base["maxLayerIndex"])
	apps := []any{}
	unknown := []any{}
	baseParts := []any{}
	for _, raw := range parts {
		part := obj(raw)
		index, known := historyIndex(part["layerIndex"])
		switch {
		case !matched || !known || index >= len(arr(obj(obj(image["metadata"])["v1"])["layers"])):
			unknown = append(unknown, raw)
		case index <= boundary:
			baseParts = append(baseParts, raw)
		default:
			apps = append(apps, raw)
		}
	}
	summary["status"] = "scanned"
	summary["partial"] = partial
	summary["base"] = base
	summary["findings"] = findingCounts(parts)
	summary["baseFindings"] = findingCounts(baseParts)
	summary["applicationComponents"] = apps
	summary["unknownComponents"] = unknown
}

func reportHeading(text, color, background string) string {
	value := `\textcolor{` + color + `}{\textsf{\textbf{` + text + `}}}`
	if background != "" {
		value = `\colorbox{` + background + `}{` + value + `}`
	}
	return `$\footnotesize ` + value + `$`
}

func countsCell(counts M) string {
	if num(counts["total"]) == 0 {
		return "0 kända fynd"
	}
	values := []string{fmt.Sprintf("🔴 **%d** kritiska", int(num(counts["critical"]))), fmt.Sprintf("🟠 **%d** höga", int(num(counts["high"])))}
	if n := int(num(counts["other"])); n > 0 {
		values = append(values, fmt.Sprintf("%d övriga", n))
	}
	if n := int(num(counts["unknown"])); n > 0 {
		values = append(values, fmt.Sprintf("%d ej bedömda", n))
	}
	return strings.Join(values, " · ")
}

func applicationCells(summary M) []string {
	base := obj(summary["base"])
	if len(base) == 0 {
		return []string{"Ursprung ej verifierat"}
	}
	packages := map[string]M{}
	for _, raw := range arr(summary["applicationComponents"]) {
		part := obj(raw)
		if num(findingCounts([]any{raw})["total"]) > 0 {
			packages[str(part["name"])+"\x00"+str(part["version"])] = part
		}
	}
	keys := []string{}
	for key := range packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := []string{}
	for _, key := range keys {
		part := packages[key]
		item := inert(str(part["name"]), 80) + " " + inert(str(part["version"]), 80)
		if fix := str(part["fixedBy"]); strings.TrimSpace(fix) != "" {
			item += " → " + inert(fix, 80)
		} else {
			// Versions from different advisories have no universal ordering
			// (Debian, RPM, Python, etc.). Do not guess a package-wide target.
			fixes := []string{}
			for _, v := range arr(part["vulns"]) {
				if fix := str(obj(v)["fixedBy"]); strings.TrimSpace(fix) != "" {
					fixes = append(fixes, fix)
				}
			}
			fixes = unique(fixes)
			if len(fixes) == 1 {
				item += " → " + inert(fixes[0], 80)
			} else if len(fixes) > 1 {
				item += " · olika fixversioner per CVE"
			} else {
				item += " · fix ej angiven"
			}
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		items = append(items, "0 kända tilläggsfynd")
	}
	if n := num(findingCounts(arr(summary["unknownComponents"]))["total"]); n > 0 {
		items = append(items, fmt.Sprintf("%d fynd med okänt ursprung", int(n)))
	}
	// Include every affected addition; long lists continue on further table
	// rows instead of a top-N selection, dropdown, or JSON attachment.
	cells := []string{}
	current := ""
	for _, item := range items {
		if current != "" && utf8.RuneCountInString(current)+utf8.RuneCountInString(item) > 320 {
			cells = append(cells, current)
			current = ""
		}
		if current != "" {
			current += "; "
		}
		current += item
	}
	return append(cells, current)
}

func imageReportMessages(result M) []M {
	rows := []struct{ namespace, image, text string }{}
	seen := map[string]bool{}
	for _, raw := range arr(result["images"]) {
		summary := obj(raw)
		base, counts, apps := "Ej verifierad", "Underlag saknas", []string{"Ej verifierat"}
		if str(summary["status"]) == "scanned" {
			if name := str(obj(summary["base"])["baseImageFullName"]); name != "" {
				base = inert(name, 300)
			}
			counts = countsCell(obj(summary["findings"]))
			if boolean(summary["partial"]) {
				counts += " · **delvis underlag**"
			}
			apps = applicationCells(summary)
		}
		for _, target := range arr(summary["targets"]) {
			ns := str(obj(target)["namespace"])
			image := str(obj(target)["image"])
			if image == "" {
				image = str(summary["image"])
			}
			key := ns + "\x00" + str(summary["imageId"]) + "\x00" + image
			if seen[key] {
				continue
			}
			seen[key] = true
			for i, app := range apps {
				baseCell, countCell, imageCell := base, counts, inert(image, 300)
				if i > 0 {
					baseCell, countCell, imageCell = "—", "—", imageCell+" (forts.)"
				}
				line := "| " + inert(ns, 63) + " | " + imageCell + " | " + baseCell + " | " + countCell + " | " + app + " |"
				rows = append(rows, struct{ namespace, image, text string }{ns, image, line})
			}
		}
	}
	if len(rows) == 0 || num(result["unscannedImages"]) > 0 {
		for _, ns := range stringsOf(result["namespaces"]) {
			status := "Inga körande images hittades"
			if incomplete(result) {
				status = "Underlag saknas · " + fmt.Sprint(int(num(result["unscannedImages"]))) + " ej identifierade images i urvalet"
			}
			rows = append(rows, struct{ namespace, image, text string }{ns, "", "| " + inert(ns, 63) + " | — | Ej verifierad | " + status + " | Ej verifierat |"})
		}
	}
	if len(rows) == 0 {
		rows = append(rows, struct{ namespace, image, text string }{text: "| — | — | Ej verifierad | Underlag saknas | Ej verifierat |"})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].namespace != rows[j].namespace {
			return rows[i].namespace < rows[j].namespace
		}
		return rows[i].image < rows[j].image
	})
	heading := func(text, color, background string) string {
		if boolean(result["inlineLatex"]) {
			return reportHeading(text, color, background)
		}
		return "**" + text + "**"
	}
	header := "| " + strings.Join([]string{
		heading("Namespace", "#182C51", "#EDF2FF"),
		heading("Image i drift", "#BC2546", "#FDEFF2"),
		heading("Basimage (ACS)", "#182C51", ""),
		heading("Fynd i imagen", "#AD610D", ""),
		heading("Appens tillägg (fynd)", "#2B56B8", ""),
	}, " | ") + " |\n| :--- | :--- | :--- | :--- | :--- |"
	first := header
	if len(stringsOf(result["alertCves"])) > 0 {
		first = "@channel **Nya kritiska CVE:er**\n\n" + first
	}
	messages := []M{}
	current, count := first, 0
	for _, row := range rows {
		if count > 0 && (count >= 6 || utf8.RuneCountInString(current)+utf8.RuneCountInString(row.text) > 4500) {
			messages = append(messages, M{"text": current})
			current, count = header, 0
		}
		current += "\n" + row.text
		count++
	}
	return append(messages, M{"text": current})
}
