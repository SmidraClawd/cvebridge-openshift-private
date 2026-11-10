package bridge

import (
	"sort"
	"strings"
)

func cveRisk(severity string) (string, int) {
	switch severity {
	case "CRITICAL_VULNERABILITY_SEVERITY":
		return "🔴 **Kritisk**", 0
	case "IMPORTANT_VULNERABILITY_SEVERITY":
		return "🟠 **Hög**", 1
	case "MODERATE_VULNERABILITY_SEVERITY":
		return "🟡 Medel", 2
	case "LOW_VULNERABILITY_SEVERITY":
		return "🔵 Låg", 3
	default:
		return "⚪ Ej bedömd", 4
	}
}

func lookupPackage(row M) string {
	name := str(row["component"])
	if strings.TrimSpace(name) == "" {
		name = "Ej angivet av ACS"
	}
	value := inert(name, 120)
	switch str(row["origin"]) {
	case "base":
		value += " · Basimage"
		if base := str(row["baseImage"]); base != "" {
			value += " (" + inert(base, 200) + ")"
		}
	case "application":
		value += " · Appens tillägg"
	default:
		value += " · Ursprung ej verifierat"
	}
	return value
}

func lookupVersion(value any) string {
	if s := strings.TrimSpace(str(value)); s != "" {
		return inert(s, 128)
	}
	return "Ej angiven av ACS"
}

func cveLookupMessages(result M) []M {
	cves := stringsOf(result["cves"])
	if len(cves) == 0 && CVE.MatchString(str(result["cve"])) {
		cves = []string{str(result["cve"])}
	}
	wanted := map[string]bool{}
	for _, cve := range cves {
		if CVE.MatchString(cve) {
			wanted[cve] = true
		}
	}
	found := map[string]bool{}
	seen := map[string]bool{}
	matches := []M{}
	for _, raw := range arr(result["rows"]) {
		row := obj(raw)
		cve := str(row["cve"])
		if !wanted[cve] {
			continue
		}
		image := str(row["displayImage"])
		if image == "" {
			image = str(row["image"])
		}
		key := strings.Join([]string{str(row["namespace"]), str(row["imageId"]), image, cve, str(row["component"]), str(row["version"]), str(row["fixedBy"])}, "\x00")
		if seen[key] {
			continue
		}
		seen[key], found[cve] = true, true
		matches = append(matches, row)
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		for _, field := range []string{"namespace", "imageId", "displayImage", "image"} {
			if str(a[field]) != str(b[field]) {
				return str(a[field]) < str(b[field])
			}
		}
		_, rankA := cveRisk(str(a["severity"]))
		_, rankB := cveRisk(str(b["severity"]))
		if rankA != rankB {
			return rankA < rankB
		}
		for _, field := range []string{"cve", "component", "version", "fixedBy"} {
			if str(a[field]) != str(b[field]) {
				return str(a[field]) < str(b[field])
			}
		}
		return false
	})
	rows := []string{}
	partial := incomplete(result)
	for _, row := range matches {
		image := str(row["displayImage"])
		if image == "" {
			image = str(row["image"])
		}
		risk, _ := cveRisk(str(row["severity"]))
		if partial {
			risk += " · **delvis underlag**"
		}
		rows = append(rows, "| "+strings.Join([]string{
			inert(str(row["namespace"]), 63), inert(image, 300), inert(str(row["cve"]), 40), risk,
			lookupPackage(row), lookupVersion(row["version"]), lookupVersion(row["fixedBy"]),
		}, " | ")+" |")
	}
	// An absent match must remain distinct from an unavailable or incomplete
	// scan. Show every requested CVE, including those with no known findings.
	for _, cve := range unique(cves) {
		if !wanted[cve] || found[cve] {
			continue
		}
		status, detail := "Ingen känd träff", "Ingen match i befintliga ACS-resultat"
		if partial {
			status, detail = "**Delvis underlag**", "Ingen känd träff; frånvaro kan inte verifieras"
		}
		if num(result["scannedImages"]) == 0 && num(result["totalImages"]) > 0 {
			status, detail = "**Underlag saknas**", "Ingen träff kan verifieras"
		} else if num(result["totalImages"]) == 0 && !partial {
			detail = "Inga körande images hittades i urvalet"
		}
		rows = append(rows, "| "+inert(scope(stringsOf(result["namespaces"])), 240)+" | — | "+inert(cve, 40)+" | "+status+" | "+detail+" | — | — |")
	}
	if len(rows) == 0 {
		rows = append(rows, "| — | — | — | Ej verifierat | Ingen giltig CVE angiven | — | — |")
	}
	header := "| " + strings.Join([]string{
		tableHeading(result, "Namespace", "#182C51", "#EDF2FF"),
		tableHeading(result, "Image i drift", "#182C51", ""),
		tableHeading(result, "CVE", "#BC2546", "#FDEFF2"),
		tableHeading(result, "Risk (ACS)", "#AD610D", ""),
		tableHeading(result, "Paket / ursprung", "#2B56B8", ""),
		tableHeading(result, "Ni har", "#AD610D", "#FFF4E8"),
		tableHeading(result, "Fix (ACS)", "#23755F", "#EAF6F1"),
	}, " | ") + " |\n| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
	return nativeTableMessages(header, rows, "")
}
