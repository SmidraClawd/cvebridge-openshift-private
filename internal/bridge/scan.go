package bridge

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
	Image      string `json:"image,omitempty"`
}
type InventoryImage struct {
	Digest, Name string
	Targets      []Target
}
type Inventory struct {
	Images                 []InventoryImage
	Pods, Missing, Records int
}

func (s *Services) query(kind, ns string, offset int) string {
	// Unquoted ACS terms also match prefixes, which the scope check rejects.
	query := fmt.Sprintf("Cluster ID:%q", s.C.Get("STACKROX_CLUSTER_ID", ""))
	if ns != allNamespaces {
		query += fmt.Sprintf("+Namespace:%q", ns)
	}
	return "/v1/" + kind + "?" + url.Values{"query": {query}, "pagination.limit": {"100"}, "pagination.offset": {strconv.Itoa(offset)}}.Encode()
}
func (s *Services) scoped(r M, ns string) bool {
	actual := str(r["namespace"])
	return NS.MatchString(actual) && (ns == allNamespaces || actual == ns) && str(r["clusterId"]) == s.C.Get("STACKROX_CLUSTER_ID", "")
}
func (s *Services) Inventory(ctx context.Context, namespaces []string, scheduled bool) (Inventory, error) {
	inv := Inventory{}
	if !validNamespaceScope(namespaces, s.C.OperationsOnly()) {
		return inv, problem(403, "Välj godkända namespaces eller * för hela det konfigurerade klustret i driftläget.")
	}
	limits, err := s.C.inventoryLimits()
	if err != nil {
		return inv, problem(503, "Botens inventeringsgränser är ogiltiga. Kontrollera SCAN_MAX-fälten i ConfigMap.")
	}
	s.acsInfo("inventory_start", M{"cluster_id": s.C.Get("STACKROX_CLUSTER_ID", ""), "namespaces": namespaces,
		"max_images": limits.Images, "max_active_pods": limits.Pods, "max_pod_records": limits.PodRecords})
	images := map[string]*InventoryImage{}
	deps := map[string]M{}
	podsSeen := map[string]bool{}
	missing := map[string]bool{}
	for _, selector := range unique(namespaces) {
		for offset := 0; ; offset += 100 {
			page, e := s.RoxRequest(ctx, s.query("pods", selector, offset), "read", nil, scheduled)
			if e != nil {
				return inv, e
			}
			pods := arr(page["pods"])
			inv.Records += len(pods)
			if inv.Records > limits.PodRecords {
				return inv, s.inventoryLimit("SCAN_MAX_POD_RECORDS", inv.Records, limits.PodRecords, len(images), len(podsSeen), inv.Records)
			}
			for _, p := range pods {
				pod := obj(p)
				if !s.scoped(pod, selector) {
					s.acsDebug("inventory_scope_mismatch", M{
						"expected_namespace":  selector,
						"actual_namespace":    str(pod["namespace"]),
						"expected_cluster_id": s.C.Get("STACKROX_CLUSTER_ID", ""),
						"actual_cluster_id":   str(pod["clusterId"]),
					})
					return inv, problem(502, "Inventeringen matchar inte godkänd omfattning.")
				}
				// Resolve the selector from each pod, then require its deployment
				// to match that exact namespace as well as the selected cluster.
				ns := str(pod["namespace"])
				live := []M{}
				for _, i := range arr(pod["liveInstances"]) {
					if !boolean(obj(i)["finished"]) {
						live = append(live, obj(i))
					}
				}
				if len(live) == 0 {
					continue
				}
				pid := str(pod["id"])
				podsSeen[pid] = true
				if len(podsSeen) > limits.Pods {
					return inv, s.inventoryLimit("SCAN_MAX_PODS", len(podsSeen), limits.Pods, len(images), len(podsSeen), inv.Records)
				}
				depID := str(pod["deploymentId"])
				if depID == "" {
					missing[ns+pid+"pending"] = true
					continue
				}
				dep := deps[depID]
				if dep == nil {
					dep, e = s.RoxRequest(ctx, "/v1/deployments/"+url.PathEscape(depID), "read", nil, scheduled)
					if e != nil {
						return inv, e
					}
					deps[depID] = dep
				}
				if !s.scoped(dep, ns) {
					return inv, problem(502, "Arbetslasten matchar inte godkänd omfattning.")
				}
				containers := map[string]M{}
				refs := [][2]string{}
				for _, c := range arr(dep["containers"]) {
					co := obj(c)
					name := str(co["name"])
					containers[name] = co
					if str(co["type"]) == "INIT" {
						refs = append(refs, [2]string{name, str(obj(co["image"])["id"])})
					}
				}
				for _, i := range live {
					refs = append(refs, [2]string{str(i["containerName"]), str(i["imageDigest"])})
				}
				for _, ref := range refs {
					full := str(obj(obj(containers[ref[0]]["image"])["name"])["fullName"])
					digest := ref[1]
					repo := strings.SplitN(full, "@", 2)[0]
					last := strings.LastIndex(repo, "/")
					if colon := strings.LastIndex(repo, ":"); colon > last {
						repo = repo[:colon]
					}
					if !Digest.MatchString(digest) || !Image.MatchString(repo) || strings.Contains(repo, "@") {
						missing[ns+pid+ref[0]] = true
						continue
					}
					entry := images[digest]
					if entry == nil {
						entry = &InventoryImage{Digest: digest, Name: repo + "@" + digest}
						images[digest] = entry
						if len(images) > limits.Images {
							return inv, s.inventoryLimit("SCAN_MAX_IMAGES", len(images), limits.Images, len(images), len(podsSeen), inv.Records)
						}
					}
					// Keep the deployed tag for display, while scanning the immutable
					// runtime digest. A rolling deployment may reference a newer image.
					display := repo + "@" + digest
					if str(obj(containers[ref[0]]["image"])["id"]) == digest {
						display = full
					}
					target := Target{Namespace: ns, Deployment: str(dep["name"]), Image: display}
					exists := false
					for _, t := range entry.Targets {
						if t == target {
							exists = true
						}
					}
					if !exists {
						entry.Targets = append(entry.Targets, target)
					}
				}
			}
			if offset == 0 || offset%1000 == 0 || len(pods) < 100 {
				s.acsInfo("inventory_progress", M{"images": len(images), "active_pods": len(podsSeen), "pod_records": inv.Records})
			}
			if len(pods) < 100 {
				break
			}
		}
	}
	keys := []string{}
	for k := range images {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		inv.Images = append(inv.Images, *images[k])
	}
	inv.Pods = len(podsSeen)
	inv.Missing = len(missing)
	return inv, nil
}
func (s *Services) DatabaseStatus(ctx context.Context) M {
	return s.databaseStatusAt(ctx, time.Now())
}
func (s *Services) databaseStatusAt(ctx context.Context, now time.Time) M {
	component := s.C.Get("STACKROX_SCANNER_COMPONENT", "SCANNER")
	max := s.C.Float("DATABASE_MAX_AGE_HOURS", 24)
	r := M{"kind": "status", "state": "unknown", "lastUpdated": nil, "ageHours": nil, "checkedAt": now.UTC().Format(time.RFC3339), "maxAgeHours": max, "component": component}
	if component != "SCANNER" && component != "SCANNER_V4" {
		r["reason"] = "Vald Scanner-komponent stöds inte."
		return r
	}
	reply, e := s.RoxRequest(ctx, "/v1/integrationhealth/vulndefinitions?component="+url.QueryEscape(component), "status", nil, false)
	if e != nil {
		r["reason"] = message(e)
		return r
	}
	stamp := str(reply["lastUpdatedTimestamp"])
	if stamp == "" {
		stamp = str(reply["lastUpdated"])
	}
	point, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || max <= 0 {
		r["reason"] = "ACS returnerade ingen giltig uppdateringstid för vald Scanner."
		return r
	}
	age := now.Sub(point).Hours()
	if age < -0.1 {
		r["reason"] = "Uppdateringstiden ligger i framtiden. Kontrollera klockorna."
		return r
	}
	if age < 0 {
		age = 0
	}
	r["lastUpdated"] = stamp
	r["ageHours"] = float64(int(age*100)) / 100
	r["state"] = "recent"
	if age > max {
		r["state"] = "stale"
	}
	return r
}
func (s *Services) Scan(ctx context.Context, namespaces []string, authorize func() error, force, scheduled bool, cves ...string) (M, error) {
	start := time.Now()
	s.acsDebug("scan_start", M{"namespaces": namespaces, "cluster_id": s.C.Get("STACKROX_CLUSTER_ID", ""), "force": force, "scheduled": scheduled})
	if e := authorize(); e != nil {
		s.acsDebug("scan_failed", M{"stage": "authorization"})
		return nil, e
	}
	inv, e := s.Inventory(ctx, namespaces, scheduled)
	if e != nil {
		s.acsDebug("scan_failed", M{"stage": "inventory", "reason": message(e)})
		return nil, e
	}
	s.acsInfo("inventory_complete", M{"pods": inv.Pods, "images": len(inv.Images), "missing_images": inv.Missing, "pod_records": inv.Records})
	rows := []any{}
	images := []any{}
	errors := []any{}
	warnings := []any{}
	scanTimes := []any{}
	failed, scanned, components, partial := 0, 0, 0, 0
	truncated := false
	wanted := map[string]bool{}
	for _, cve := range cves {
		wanted[cve] = true
	}
	for number, entry := range inv.Images {
		summary := M{"imageId": entry.Digest, "image": entry.Name, "targets": reportTargets(entry), "status": "failed"}
		images = append(images, summary)
		s.acsDebug("image_start", M{"image": entry.Name, "number": number + 1, "total_images": len(inv.Images)})
		if e := authorize(); e != nil {
			return nil, e
		}
		if time.Since(start) > 30*time.Minute {
			failed += len(inv.Images) - number
			for _, remaining := range inv.Images[number+1:] {
				images = append(images, M{"imageId": remaining.Digest, "image": remaining.Name, "targets": reportTargets(remaining), "status": "failed"})
			}
			errors = append(errors, M{"reason": "Körningens tidsgräns nåddes"})
			break
		}
		attempt := time.Now()
		var image M
		var err error
		if force {
			p := M{"imageName": entry.Name, "force": true}
			if s.C.Flag("STACKROX_DELEGATE_SCAN", false) {
				p["cluster"] = s.C.Get("STACKROX_CLUSTER_ID", "")
				p["namespace"] = entry.Targets[0].Namespace
			}
			image, err = s.RoxRequest(ctx, "/v1/images/scan", "scan", p, scheduled)
		} else {
			image, err = s.RoxRequest(ctx, "/v1/images/"+url.PathEscape(entry.Digest)+"?strip_description=true", "read", nil, scheduled)
		}
		scan := obj(image["scan"])
		stamp := str(scan["scanTime"])
		point, parseErr := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || parseErr != nil || str(image["id"]) != entry.Digest || has(stringsOf(image["notes"]), "MISSING_SCAN_DATA") || (force && point.Before(attempt.Add(-2*time.Second))) || point.After(time.Now().Add(5*time.Minute)) {
			reason := "scan_time_outside_expected_range"
			switch {
			case err != nil:
				reason = "acs_request_failed"
			case parseErr != nil:
				reason = "missing_or_invalid_scan_time"
			case str(image["id"]) != entry.Digest:
				reason = "image_digest_mismatch"
			case has(stringsOf(image["notes"]), "MISSING_SCAN_DATA"):
				reason = "missing_scan_data"
			}
			s.acsDebug("image_failed", M{"image": entry.Name, "reason": reason})
			failed++
			errors = append(errors, M{"image": entry.Name, "reason": "Ett komplett och aktuellt skanningsresultat kunde inte verifieras"})
			continue
		}
		scanned++
		scanTimes = append(scanTimes, M{"image": entry.Name, "scanTime": stamp})
		parts := arr(scan["components"])
		components += len(parts)
		notes := stringsOf(image["notes"])
		if len(notes) > 0 {
			warnings = append(warnings, M{"image": entry.Name, "notes": notes})
		}
		sn := []string{}
		for _, n := range stringsOf(scan["notes"]) {
			if n != "UNSET" {
				sn = append(sn, n)
			}
		}
		if len(sn) > 0 || has(notes, "MISSING_METADATA") || len(parts) == 0 {
			partial++
			if len(sn) == 0 {
				sn = []string{"PARTIAL_SCAN_DATA"}
			}
			warnings = append(warnings, M{"image": entry.Name, "scanNotes": sn})
		}
		addImageSummary(summary, image, len(sn) > 0 || has(notes, "MISSING_METADATA") || len(parts) == 0)
		s.logImageOrigin(summary, image)
		for _, p := range parts {
			part := obj(p)
			origin := componentOrigin(part, image, obj(summary["base"]))
			for _, v := range arr(part["vulns"]) {
				vuln := obj(v)
				cve := strings.ToUpper(str(vuln["cve"]))
				if !CVE.MatchString(cve) {
					continue
				}
				if len(wanted) > 0 && !wanted[cve] {
					continue
				}
				if len(rows)+len(entry.Targets) > 20000 {
					truncated = true
					continue
				}
				for _, t := range entry.Targets {
					rows = append(rows, M{"namespace": t.Namespace, "deployment": t.Deployment, "image": entry.Name, "displayImage": t.Image, "imageId": entry.Digest, "component": str(part["name"]), "version": str(part["version"]), "source": str(part["source"]), "location": str(part["location"]), "origin": origin, "baseImage": str(obj(summary["base"])["baseImageFullName"]), "cve": cve, "fixedBy": str(vuln["fixedBy"]), "cvss": num(vuln["cvss"]), "severity": str(vuln["severity"])})
				}
			}
		}
	}
	if e := authorize(); e != nil {
		return nil, e
	}
	mode := "report"
	if force {
		mode = "scan"
	}
	s.acsDebug("scan_complete", M{"mode": mode, "scanned_images": scanned, "failed_images": failed, "partial_images": partial, "duration_ms": time.Since(start).Milliseconds()})
	return M{"kind": "scan", "mode": mode, "namespaces": namespaces, "rows": rows, "images": images, "scannedImages": scanned, "totalImages": len(inv.Images), "failedImages": failed, "unscannedImages": inv.Missing, "partialImages": partial, "pods": inv.Pods, "components": components, "errors": errors, "warnings": warnings, "truncated": truncated, "scanTimes": scanTimes, "database": s.DatabaseStatus(ctx), "finishedAt": time.Now().UTC().Format(time.RFC3339), "durationSeconds": int(time.Since(start).Seconds())}, nil
}
func (s *Services) Lookup(ctx context.Context, query string, ns []string, authorize func() error) (M, error) {
	// Use the same live pod inventory and immutable digests as a scan. No new scan
	// is requested for a CVE lookup; coverage and partial data remain explicit.
	cves, e := normalizeCVEs(cveTerms(query))
	if e != nil {
		return nil, e
	}
	// Filter before Scan's row limit so unrelated findings cannot consume
	// the search budget. All requested CVEs share one scoped inventory pass.
	r, e := s.Scan(ctx, ns, authorize, false, false, cves...)
	if e != nil {
		return nil, e
	}
	r["kind"] = "lookup"
	r["cves"] = cves
	if len(cves) == 1 {
		r["cve"] = cves[0]
	}
	return r, nil
}
func incomplete(r M) bool {
	return num(r["failedImages"])+num(r["unscannedImages"])+num(r["partialImages"]) > 0 || boolean(r["truncated"])
}
func scope(ns []string) string {
	if allNamespaceScope(ns) {
		return "Alla namespaces i valt kluster"
	}
	if len(ns) > 3 {
		return strings.Join(ns[:3], " · ") + fmt.Sprintf(" · +%d fler", len(ns)-3)
	}
	return strings.Join(ns, " · ")
}
