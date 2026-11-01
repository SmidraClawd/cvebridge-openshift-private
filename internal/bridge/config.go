package bridge

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

// ReadEnv reads data, never shell code. Dollar signs and backticks stay literal.
func ReadEnv(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 1024*1024)
	for line := 1; scan.Scan(); line++ {
		s := strings.TrimSpace(scan.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(k) {
			return nil, fmt.Errorf("invalid env field at line %d", line)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate env field %s", k)
		}
		if len(v) > 0 && (v[0] == '\'' || v[0] == '"') {
			if len(v) < 2 || v[len(v)-1] != v[0] {
				return nil, fmt.Errorf("unclosed quote at line %d", line)
			}
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, scan.Err()
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
	c := Config{Env: m}
	for _, k := range []string{"CVE_ALERTS_ENABLED", "CVE_ALERT_FIRST_REPORT", "STACKROX_DELEGATE_SCAN"} {
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
		if e := read(p.k, p.v); e != nil {
			return c, e
		}
	}
	for ch, ns := range c.Scopes {
		if !ID.MatchString(ch) || len(ns) == 0 || len(ns) > 100 {
			return c, fmt.Errorf("invalid channel scope")
		}
		for _, n := range ns {
			if !NS.MatchString(n) {
				return c, fmt.Errorf("invalid namespace")
			}
		}
		if p := c.Policies[ch]; p != "" && p != "common" && p != "requester" {
			return c, fmt.Errorf("invalid sharing policy")
		}
	}
	for ch, ns := range c.ScheduleScopes {
		if len(ns) == 0 || len(ns) > 100 || len(intersect(ns, c.Scopes[ch])) != len(unique(ns)) {
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
	if len(c.ScheduleScopes) > 0 && !regexp.MustCompile(`^system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+$`).MatchString(c.Get("SCHEDULE_SERVICE_USER", "")) {
		return c, fmt.Errorf("SCHEDULE_SERVICE_USER must be the reporter service account")
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
	return c, nil
}
