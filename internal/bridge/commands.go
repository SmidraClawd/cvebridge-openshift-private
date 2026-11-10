package bridge

import (
	"strings"
	"unicode"
)

const maxLookupCVEs = 20

func cveTerms(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r == ',' })
}

func normalizeCVEs(terms []string) ([]string, error) {
	cves := []string{}
	for _, term := range terms {
		cve := strings.ToUpper(term)
		if !CVE.MatchString(cve) {
			return nil, problem(400, "Ange giltiga CVE-ID:n, exempelvis /cve CVE-2025-47273 CVE-2022-40897 [namespace].")
		}
		cves = append(cves, cve)
	}
	cves = unique(cves)
	if len(cves) == 0 || len(cves) > maxLookupCVEs {
		return nil, problem(400, "Ange 1–20 olika CVE:er, separerade med mellanslag eller kommatecken.")
	}
	return cves, nil
}

func parseSlashCommand(text string) (string, []string, error) {
	args := strings.Fields(text)
	if len(args) == 0 || (len(args) == 1 && (strings.EqualFold(args[0], "help") || strings.EqualFold(args[0], "hjälp"))) {
		return "help", nil, nil
	}
	command := strings.ToLower(args[0])
	switch command {
	case "status", "sensor", "schedule":
		if len(args) != 1 {
			return "", nil, problem(400, "Kontrollera argumenten med /cve help.")
		}
		return command, nil, nil
	case "scan", "report":
		if len(args) == 1 {
			return command, nil, nil
		}
		if len(args) != 2 || !NS.MatchString(args[1]) {
			return "", nil, problem(400, "Använd /cve scan [namespace] eller /cve report [namespace].")
		}
		return command, []string{args[1]}, nil
	case "search":
		args = args[1:]
	}
	terms := cveTerms(strings.Join(args, " "))
	namespaces := []string{}
	if len(terms) > 0 {
		last := terms[len(terms)-1]
		if !strings.HasPrefix(strings.ToUpper(last), "CVE-") && NS.MatchString(last) {
			namespaces = append(namespaces, last)
			terms = terms[:len(terms)-1]
		}
	}
	cves, err := normalizeCVEs(terms)
	if err != nil {
		return "", nil, err
	}
	return strings.Join(cves, ","), namespaces, nil
}
