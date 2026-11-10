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
	base, _ := matchedBaseWithReason(image)
	return base
}

func matchedBaseWithReason(image M) (M, string) {
	layers := arr(obj(obj(image["metadata"])["v1"])["layers"])
	if len(layers) == 0 {
		return M{}, "missing_layer_history"
	}
	if len(arr(image["baseImageInfo"])) == 0 {
		return M{}, "no_base_image_match"
	}
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
		return M{}, "ambiguous_base_image_match"
	}
	if len(best) == 0 {
		return best, "invalid_base_image_match"
	}
	return best, "verified"
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

// Keep only the values rendered in the table. In particular, do not retain
// every vulnerability object for every unknown-origin component across a
// cluster-wide run. The full current image is still used for CVE rows/alerts.
func reportComponent(part M) M {
	fixes := []string{}
	for _, raw := range arr(part["vulns"]) {
		if fix := str(obj(raw)["fixedBy"]); strings.TrimSpace(fix) != "" {
			fixes = append(fixes, fix)
		}
	}
	return M{"name": str(part["name"]), "version": str(part["version"]), "fixedBy": str(part["fixedBy"]),
		"findings": findingCounts([]any{part}), "fixVersions": unique(fixes)}
}

func addImageSummary(summary, image M, partial bool) {
	parts := arr(obj(image["scan"])["components"])
	base, reason := matchedBaseWithReason(image)
	apps := []any{}
	unknown := []any{}
	baseParts := []any{}
	for _, raw := range parts {
		switch componentOrigin(obj(raw), image, base) {
		case "base":
			baseParts = append(baseParts, raw)
		case "application":
			apps = append(apps, raw)
		default:
			unknown = append(unknown, raw)
		}
	}
	summary["status"] = "scanned"
	summary["partial"] = partial
	summary["base"] = base
	summary["baseReason"] = reason
	summary["findings"] = findingCounts(parts)
	summary["baseFindings"] = findingCounts(baseParts)
	summary["unknownFindings"] = findingCounts(unknown)
	compactApps := []any{}
	for _, raw := range apps {
		compactApps = append(compactApps, reportComponent(obj(raw)))
	}
	compactUnknown := []any{}
	for _, raw := range unknown {
		part := obj(raw)
		compactUnknown = append(compactUnknown, M{"name": str(part["name"]), "version": str(part["version"])})
	}
	summary["applicationComponents"] = compactApps
	summary["unknownComponents"] = compactUnknown
}

// Explain a conservative origin decision even when LOG_LEVEL is info. Only
// counts and validated image references are logged, never raw ACS responses.
func (s *Services) logImageOrigin(summary, image M) {
	unknown := arr(summary["unknownComponents"])
	apps := arr(summary["applicationComponents"])
	parts := arr(obj(image["scan"])["components"])
	layers := arr(obj(obj(image["metadata"])["v1"])["layers"])
	reason, state := str(summary["baseReason"]), "unknown"
	hint := "ACS saknar tillräckligt underlag för att skilja basimage från appens tillägg."
	if reason == "verified" {
		state, hint = "verified", "Basimage och paketursprung kunde verifieras mot ACS lagerhistorik."
		if len(unknown) > 0 {
			state, reason = "partial", "component_layer_index_unavailable"
			hint = "Basimagen är verifierad, men vissa paket saknar giltigt layerIndex. Dessa får okänt ursprung."
		}
	} else {
		switch reason {
		case "no_base_image_match":
			hint = "ACS returnerade ingen basimagematchning (baseImageInfo). Kontrollera basimagereferenser och matchning i ACS."
		case "missing_layer_history":
			hint = "ACS returnerade ingen lagerhistorik (metadata.v1.layers). Basimage och paketursprung kan inte verifieras."
		case "invalid_base_image_match":
			hint = "ACS basimagematchningar saknar giltigt namn, digest eller maxLayerIndex inom lagerhistoriken."
		case "ambiguous_base_image_match":
			hint = "ACS returnerade olika basimagedigests med samma lagergräns. Boten väljer inte en på gissning."
		}
	}
	missing, invalid, outside := 0, 0, 0
	for _, raw := range parts {
		part := obj(raw)
		if part["layerIndex"] == nil {
			missing++
		} else if index, ok := historyIndex(part["layerIndex"]); !ok {
			invalid++
		} else if index >= len(layers) {
			outside++
		}
	}
	s.acsInfo("image_origin", M{
		"image": str(summary["image"]), "state": state, "reason": reason, "hint": hint,
		"history_layers": len(layers), "base_matches": len(arr(image["baseImageInfo"])),
		"base_components": len(parts) - len(apps) - len(unknown), "application_components": len(apps), "unknown_components": len(unknown),
		"missing_component_layer_index": missing, "invalid_component_layer_index": invalid, "out_of_range_component_layer_index": outside,
	})
}

func componentOrigin(part, image, base M) string {
	boundary, matched := historyIndex(base["maxLayerIndex"])
	index, known := historyIndex(part["layerIndex"])
	if !matched || !known || index >= len(arr(obj(obj(image["metadata"])["v1"])["layers"])) {
		return "unknown"
	}
	if index <= boundary {
		return "base"
	}
	return "application"
}

func reportHeading(text, color, background string) string {
	value := `\textcolor{` + color + `}{\textsf{\textbf{` + text + `}}}`
	if background != "" {
		value = `\colorbox{` + background + `}{` + value + `}`
	}
	return `$\footnotesize ` + value + `$`
}

func tableHeading(result M, text, color, background string) string {
	if boolean(result["inlineLatex"]) {
		return reportHeading(text, color, background)
	}
	return "**" + text + "**"
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
		counts := obj(part["findings"])
		if len(counts) == 0 {
			counts = findingCounts([]any{raw})
		}
		if num(counts["total"]) > 0 {
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
			fixes := append([]string{}, stringsOf(part["fixVersions"])...)
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
	unknownCounts := obj(summary["unknownFindings"])
	if len(unknownCounts) == 0 {
		unknownCounts = findingCounts(arr(summary["unknownComponents"]))
	}
	if n := num(unknownCounts["total"]); n > 0 {
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
			if ns == allNamespaces {
				ns = scope([]string{allNamespaces})
			}
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
	header := "| " + strings.Join([]string{
		tableHeading(result, "Namespace", "#182C51", "#EDF2FF"),
		tableHeading(result, "Image i drift", "#BC2546", "#FDEFF2"),
		tableHeading(result, "Basimage (ACS)", "#182C51", ""),
		tableHeading(result, "Fynd i imagen", "#AD610D", ""),
		tableHeading(result, "Appens tillägg (fynd)", "#2B56B8", ""),
	}, " | ") + " |\n| :--- | :--- | :--- | :--- | :--- |"
	prefix := ""
	if len(stringsOf(result["alertCves"])) > 0 {
		prefix = "@channel **Nya kritiska CVE:er**\n\n"
	}
	lines := []string{}
	for _, row := range rows {
		lines = append(lines, row.text)
	}
	return nativeTableMessages(header, lines, prefix)
}

func nativeTableMessages(header string, rows []string, prefix string) []M {
	messages := []M{}
	current, count := prefix+header, 0
	for _, row := range rows {
		if count > 0 && (count >= 6 || utf8.RuneCountInString(current)+utf8.RuneCountInString(row) > 4500) {
			messages = append(messages, M{"text": current})
			current, count = header, 0
		}
		current += "\n" + row
		count++
	}
	return append(messages, M{"text": current})
}
