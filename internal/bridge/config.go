package bridge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type M = map[string]any
type Problem struct {
	Status  int
	Message string
}

func (p *Problem) Error() string               { return p.Message }
func problem(status int, message string) error { return &Problem{status, message} }
func str(v any) string                         { s, _ := v.(string); return s }
func obj(v any) M {
	m, _ := v.(map[string]any)
	if m == nil {
		return M{}
	}
	return m
}
func arr(v any) []any { a, _ := v.([]any); return a }
func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
func boolean(v any) bool { b, _ := v.(bool); return b }
func stringsOf(v any) []string {
	if s, ok := v.([]string); ok {
		return s
	}
	var out []string
	for _, a := range arr(v) {
		out = append(out, str(a))
	}
	return out
}
func unique(s []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range s {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	sort.Strings(out)
	return out
}
func has(s []string, v string) bool {
	for _, a := range s {
		if a == v {
			return true
		}
	}
	return false
}
func intersect(a, b []string) []string {
	r := []string{}
	for _, v := range a {
		if has(b, v) {
			r = append(r, v)
		}
	}
	return unique(r)
}
func same(a, b any) bool  { return encode(a) == encode(b) }
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }
func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

var ID = regexp.MustCompile(`^[a-z0-9]{26}$`)
var NS = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var CVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
var Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var Image = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*$`)

func validUser(s string) bool {
	if s == "" || len(s) > 256 || strings.HasPrefix(s, "system:") {
		return false
	}
	for _, r := range s {
		if r < 33 || r == 127 {
			return false
		}
	}
	return true
}

type Config struct {
	Env                              map[string]string
	Scopes, ScheduleScopes, Managers map[string][]string
	Policies, Users                  map[string]string
}

func (c Config) Get(k, d string) string {
	if v, ok := c.Env[k]; ok {
		return v
	}
	return d
}
func (c Config) Flag(k string, d bool) bool { s := c.Get(k, strconv.FormatBool(d)); return s == "true" }
func (c Config) Float(k string, d float64) float64 {
	n, e := strconv.ParseFloat(c.Get(k, strconv.FormatFloat(d, 'f', -1, 64)), 64)
	if e != nil {
		return d
	}
	return n
}
func ConfigFromEnv() (Config, error) {
	m := map[string]string{}
	for _, s := range os.Environ() {
		k, v, _ := strings.Cut(s, "=")
		m[k] = v
	}
	return NewConfig(m)
}
func NewConfig(m map[string]string) (Config, error) {
	var err error
	m, err = configurationDefaults(m)
	if err != nil {
		return Config{}, err
	}
	c := Config{Env: m}
	if mode := c.Get("ACCESS_MODE", ""); mode != "operations" && mode != "per-user" {
		return c, fmt.Errorf("ACCESS_MODE must be operations or per-user")
	}
	if _, err := c.inventoryLimits(); err != nil {
		return c, err
	}
	for _, k := range []string{"CVE_ALERTS_ENABLED", "CVE_ALERT_FIRST_REPORT", "STACKROX_DELEGATE_SCAN", "SENSOR_MONITOR_ENABLED"} {
		if v, ok := m[k]; ok && v != "true" && v != "false" {
			return c, fmt.Errorf("%s must be true or false", k)
		}
	}
	for _, k := range []string{"CVE_ALERT_MIN_CVSS", "DATABASE_MAX_AGE_HOURS"} {
		if v, ok := m[k]; ok {
			n, e := strconv.ParseFloat(v, 64)
			if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || (k == "DATABASE_MAX_AGE_HOURS" && n <= 0) {
				return c, fmt.Errorf("invalid %s", k)
			}
		}
	}
	read := func(k string, d any) error {
		s := c.Get(k, "{}")
		if e := json.Unmarshal([]byte(s), d); e != nil {
			return fmt.Errorf("invalid JSON in %s", k)
		}
		return nil
	}
	for _, p := range []struct {
		k string
		v any
	}{{"MATTERMOST_CHANNEL_SCOPES", &c.Scopes}, {"MATTERMOST_SCHEDULE_SCOPES", &c.ScheduleScopes}, {"MATTERMOST_SCHEDULE_MANAGERS", &c.Managers}, {"MATTERMOST_CHANNEL_POLICIES", &c.Policies}, {"MATTERMOST_KUBE_USER_MAP", &c.Users}} {
		if c.OperationsOnly() && p.k != "MATTERMOST_CHANNEL_SCOPES" && p.k != "MATTERMOST_SCHEDULE_SCOPES" {
			continue
		}
		if e := read(p.k, p.v); e != nil {
			return c, e
		}
	}
	for ch, ns := range c.Scopes {
		if !ID.MatchString(ch) || !validNamespaceScope(ns, c.OperationsOnly()) {
			return c, fmt.Errorf("invalid channel scope")
		}
		if p := c.Policies[ch]; p != "" && p != "common" && p != "requester" {
			return c, fmt.Errorf("invalid sharing policy")
		}
	}
	for ch, ns := range c.ScheduleScopes {
		if !validNamespaceScope(ns, c.OperationsOnly()) || !namespaceSubset(ns, c.Scopes[ch]) {
			return c, fmt.Errorf("schedule scope must be within channel scope")
		}
	}
	for ch, users := range c.Managers {
		if len(c.ScheduleScopes[ch]) == 0 {
			return c, fmt.Errorf("manager channel must allow scheduling")
		}
		for _, u := range users {
			if !ID.MatchString(u) {
				return c, fmt.Errorf("invalid manager ID")
			}
		}
	}
	for id, u := range c.Users {
		if !ID.MatchString(id) || !validUser(u) {
			return c, fmt.Errorf("invalid approved user mapping")
		}
	}
	if !c.OperationsOnly() && len(c.ScheduleScopes) > 0 && !regexp.MustCompile(`^system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+$`).MatchString(c.Get("SCHEDULE_SERVICE_USER", "")) {
		return c, fmt.Errorf("SCHEDULE_SERVICE_USER must be the reporter service account")
	}
	if c.OperationsOnly() {
		ch := c.Get("MATTERMOST_CHANNEL_ID", "")
		if !ID.MatchString(ch) || len(c.Scopes) != 1 || len(c.Scopes[ch]) == 0 {
			return c, fmt.Errorf("configure one MATTERMOST_CHANNEL_ID and its SCAN_NAMESPACES for operations")
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(c.Get("STACKROX_CLUSTER_ID", "")) {
		return c, fmt.Errorf("STACKROX_CLUSTER_ID is required")
	}
	for _, k := range []string{"MATTERMOST_INTERNAL_URL", "STACKROX_URL"} {
		u, e := url.Parse(c.Get(k, ""))
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return c, fmt.Errorf("invalid %s", k)
		}
	}
	if n := c.Float("CVE_ALERT_MIN_CVSS", 9); n < 0 || n > 10 {
		return c, fmt.Errorf("invalid CVE_ALERT_MIN_CVSS")
	}
	if ch := c.Get("DATABASE_MONITOR_CHANNEL_ID", ""); ch != "" {
		if !ID.MatchString(ch) {
			return c, fmt.Errorf("DATABASE_MONITOR_CHANNEL_ID must be a stable 26-character Mattermost channel ID")
		}
		component := c.Get("STACKROX_SCANNER_COMPONENT", "")
		if component != "SCANNER" && component != "SCANNER_V4" {
			return c, fmt.Errorf("database monitoring requires STACKROX_SCANNER_COMPONENT=SCANNER or SCANNER_V4")
		}
	}
	return c, nil
}

// configurationDefaults expands the short installation form without inventing
// identities, grants or credentials. Explicit advanced settings take priority.
func configurationDefaults(input map[string]string) (map[string]string, error) {
	m := make(map[string]string, len(input)+12)
	for k, v := range input {
		m[k] = v
	}
	// The short private installation uses one scoped ACS API token. Explicit
	// per-operation credentials remain available for installations that need them.
	for _, key := range []string{"STACKROX_SCAN_TOKEN", "STACKROX_STATUS_TOKEN", "STACKROX_SCHEDULE_TOKEN"} {
		if _, explicit := m[key]; !explicit {
			m[key] = m["STACKROX_TOKEN"]
		}
	}
	for k, v := range map[string]string{
		"ACCESS_MODE": "operations",
		"NAMESPACE":   "cvebridge", "STACKROX_URL": "https://central.stackrox.svc:443",
		"STACKROX_SCANNER_COMPONENT": "SCANNER_V4", "SCHEDULE_DEFAULT_TIMEZONE": "Europe/Stockholm",
		"DATABASE_MAX_AGE_HOURS": "24", "CVE_ALERTS_ENABLED": "true", "CVE_ALERT_MIN_CVSS": "9", "CVE_ALERT_FIRST_REPORT": "false",
		"SENSOR_MONITOR_ENABLED": "false",
	} {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	if webhook, ok := m["WEBHOOK_URL"]; ok {
		if legacy, exists := m["WEBHOOK_PUBLIC_URL"]; exists && legacy != webhook {
			return nil, fmt.Errorf("use one webhook address: WEBHOOK_URL and WEBHOOK_PUBLIC_URL disagree")
		}
	} else if legacy, ok := m["WEBHOOK_PUBLIC_URL"]; ok {
		m["WEBHOOK_URL"] = legacy
	} else {
		m["WEBHOOK_URL"] = "http://cvebridge-webhook." + m["NAMESPACE"] + ".svc:8001"
	}
	if _, ok := m["SCHEDULE_SERVICE_USER"]; !ok {
		m["SCHEDULE_SERVICE_USER"] = "system:serviceaccount:" + m["NAMESPACE"] + ":cvebridge-reporter"
	}
	if ch := m["MATTERMOST_CHANNEL_ID"]; ch != "" {
		if !ID.MatchString(ch) {
			return nil, fmt.Errorf("MATTERMOST_CHANNEL_ID must be a stable 26-character Mattermost channel ID")
		}
		if _, ok := m["MATTERMOST_CHANNEL_SCOPES"]; !ok {
			names := []string{}
			for _, value := range strings.Split(m["SCAN_NAMESPACES"], ",") {
				n := strings.TrimSpace(value)
				names = append(names, n)
			}
			if !validNamespaceScope(names, m["ACCESS_MODE"] == "operations") {
				return nil, fmt.Errorf("SCAN_NAMESPACES must list approved namespace names, or be * alone in operations mode")
			}
			m["MATTERMOST_CHANNEL_SCOPES"] = encode(map[string][]string{ch: unique(names)})
		}
		if _, ok := m["MATTERMOST_SCHEDULE_SCOPES"]; !ok {
			var scopes map[string][]string
			if e := json.Unmarshal([]byte(m["MATTERMOST_CHANNEL_SCOPES"]), &scopes); e != nil {
				return nil, fmt.Errorf("invalid JSON in MATTERMOST_CHANNEL_SCOPES")
			}
			if len(scopes[ch]) == 0 {
				return nil, fmt.Errorf("MATTERMOST_CHANNEL_ID must have approved namespaces")
			}
			m["MATTERMOST_SCHEDULE_SCOPES"] = encode(map[string][]string{ch: scopes[ch]})
		}
	}
	return m, nil
}
