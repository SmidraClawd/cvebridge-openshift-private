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
}
type InventoryImage struct {
	Digest, Name string
	Targets      []Target
}
type Inventory struct {
	Images        []InventoryImage
	Pods, Missing int
}

func (s *Services) query(kind, ns string, offset int) string {
	return "/v1/" + kind + "?" + url.Values{"query": {"Cluster ID:" + s.C.Get("STACKROX_CLUSTER_ID", "") + "+Namespace:" + ns}, "pagination.limit": {"100"}, "pagination.offset": {strconv.Itoa(offset)}}.Encode()
}
func (s *Services) scoped(r M, ns string) bool {
	return str(r["namespace"]) == ns && str(r["clusterId"]) == s.C.Get("STACKROX_CLUSTER_ID", "")
}
func (s *Services) Inventory(ctx context.Context, namespaces []string, scheduled bool) (Inventory, error) {
	inv := Inventory{}
	images := map[string]*InventoryImage{}
	deps := map[string]M{}
	podsSeen := map[string]bool{}
	missing := map[string]bool{}
	for _, ns := range namespaces {
		for offset := 0; ; offset += 100 {
			page, e := s.RoxRequest(ctx, s.query("pods", ns, offset), "read", nil, scheduled)
			if e != nil {
				return inv, e
			}
			pods := arr(page["pods"])
			for _, p := range pods {
				pod := obj(p)
				if !s.scoped(pod, ns) {
					return inv, problem(502, "Inventeringen matchar inte godkänd omfattning.")
				}
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
					}
					target := Target{ns, str(dep["name"])}
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
			if len(podsSeen) > 2000 || len(images) > 100 || offset > 10000 {
				return inv, problem(413, "Urvalet är för stort. Välj ett namespace.")
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
	component := s.C.Get("STACKROX_SCANNER_COMPONENT", "SCANNER")
	max := s.C.Float("DATABASE_MAX_AGE_HOURS", 24)
	r := M{"kind": "status", "state": "unknown", "lastUpdated": nil, "ageHours": nil, "checkedAt": time.Now().UTC().Format(time.RFC3339), "maxAgeHours": max, "component": component}
	if component != "SCANNER" && component != "SCANNER_V4" {
		return r
	}
	reply, e := s.RoxRequest(ctx, "/v1/integrationhealth/vulndefinitions?component="+url.QueryEscape(component), "status", nil, false)
	if e != nil {
		return r
	}
	stamp := str(reply["lastUpdatedTimestamp"])
	if stamp == "" {
		stamp = str(reply["lastUpdated"])
	}
	point, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || max <= 0 {
		return r
	}
	age := time.Since(point).Hours()
	if age < -0.1 {
		return r
	}
	r["lastUpdated"] = stamp
	r["ageHours"] = float64(int(age*100)) / 100
	r["state"] = "recent"
	if age > max {
		r["state"] = "stale"
	}
	return r
}
func (s *Services) Scan(ctx context.Context, namespaces []string, authorize func() error, force, scheduled bool) (M, error) {
	start := time.Now()
	if e := authorize(); e != nil {
		return nil, e
	}
	inv, e := s.Inventory(ctx, namespaces, scheduled)
	if e != nil {
		return nil, e
	}
	rows := []any{}
	errors := []any{}
	warnings := []any{}
	scanTimes := []any{}
	failed, scanned, components, partial := 0, 0, 0, 0
	truncated := false
	for number, entry := range inv.Images {
		if e := authorize(); e != nil {
			return nil, e
		}
		if time.Since(start) > 30*time.Minute {
			failed += len(inv.Images) - number
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
		for _, p := range parts {
			part := obj(p)
			for _, v := range arr(part["vulns"]) {
				vuln := obj(v)
				cve := strings.ToUpper(str(vuln["cve"]))
				if !CVE.MatchString(cve) {
					continue
				}
				if len(rows)+len(entry.Targets) > 20000 {
					truncated = true
					continue
				}
				for _, t := range entry.Targets {
					rows = append(rows, M{"namespace": t.Namespace, "deployment": t.Deployment, "image": entry.Name, "imageId": entry.Digest, "component": str(part["name"]), "version": str(part["version"]), "source": str(part["source"]), "location": str(part["location"]), "cve": cve, "fixedBy": str(vuln["fixedBy"]), "cvss": num(vuln["cvss"])})
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
	return M{"kind": "scan", "mode": mode, "namespaces": namespaces, "rows": rows, "scannedImages": scanned, "totalImages": len(inv.Images), "failedImages": failed, "unscannedImages": inv.Missing, "partialImages": partial, "pods": inv.Pods, "components": components, "errors": errors, "warnings": warnings, "truncated": truncated, "scanTimes": scanTimes, "database": s.DatabaseStatus(ctx), "finishedAt": time.Now().UTC().Format(time.RFC3339), "durationSeconds": int(time.Since(start).Seconds())}, nil
}
func (s *Services) Lookup(ctx context.Context, cve string, ns []string, authorize func() error) (M, error) {
	// Use the same live pod inventory and immutable digests as a scan. No new scan
	// is requested for a CVE lookup; coverage and partial data remain explicit.
	r, e := s.Scan(ctx, ns, authorize, false, false)
	if e != nil {
		return nil, e
	}
	rows := []any{}
	for _, v := range arr(r["rows"]) {
		if str(obj(v)["cve"]) == cve {
			rows = append(rows, v)
		}
	}
	r["kind"] = "lookup"
	r["cve"] = cve
	r["rows"] = rows
	return r, nil
}
func incomplete(r M) bool {
	return num(r["failedImages"])+num(r["unscannedImages"])+num(r["partialImages"]) > 0 || boolean(r["truncated"])
}
func scope(ns []string) string {
	if len(ns) > 3 {
		return strings.Join(ns[:3], " · ") + fmt.Sprintf(" · +%d fler", len(ns)-3)
	}
	return strings.Join(ns, " · ")
}
