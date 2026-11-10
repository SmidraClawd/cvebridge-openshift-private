package bridge

import (
	"fmt"
	"strconv"
)

type inventoryLimits struct {
	Images, Pods, PodRecords int
}

// Defaults allow a whole cluster without adding installation questions. Bounds
// remain explicit so an unexpectedly large API result cannot grow indefinitely.
func (c Config) inventoryLimits() (inventoryLimits, error) {
	limits := inventoryLimits{Images: 1000, Pods: 20000, PodRecords: 100000}
	for _, rule := range []struct {
		key   string
		value *int
		max   int
	}{
		{"SCAN_MAX_IMAGES", &limits.Images, 10000},
		{"SCAN_MAX_PODS", &limits.Pods, 100000},
		{"SCAN_MAX_POD_RECORDS", &limits.PodRecords, 1000000},
	} {
		n, err := strconv.Atoi(c.Get(rule.key, strconv.Itoa(*rule.value)))
		if err != nil || n < 1 || n > rule.max {
			return limits, fmt.Errorf("%s must be an integer between 1 and %d", rule.key, rule.max)
		}
		*rule.value = n
	}
	return limits, nil
}

func (s *Services) inventoryLimit(key string, count, limit, images, pods, records int) error {
	label := map[string]string{
		"SCAN_MAX_IMAGES": "unika images", "SCAN_MAX_PODS": "aktiva pods", "SCAN_MAX_POD_RECORDS": "lästa podposter",
	}[key]
	hint := fmt.Sprintf("Höj %s i ConfigMap och starta om boten, eller välj ett namespace. Inga images har skannats i denna körning.", key)
	s.acsInfo("inventory_limit", M{"setting": key, "count": count, "limit": limit,
		"images": images, "active_pods": pods, "pod_records": records, "hint": hint})
	return problem(413, fmt.Sprintf("Inventeringen hittade %d %s; gränsen är %d (%s). %s", count, label, limit, key, hint))
}
