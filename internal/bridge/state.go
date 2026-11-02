package bridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"
)

var Days = []string{"Måndag", "Tisdag", "Onsdag", "Torsdag", "Fredag", "Lördag", "Söndag"}

type ScheduleConfig struct {
	Days       []int    `json:"days"`
	Times      []string `json:"times"`
	Timezone   string   `json:"timezone"`
	Mode       string   `json:"mode"`
	Namespaces []string `json:"namespaces"`
	Policy     string   `json:"sharingPolicy"`
}
type Schedule struct {
	Channel  string         `json:"channel_id"`
	Revision int            `json:"revision"`
	Config   ScheduleConfig `json:"config"`
	Enabled  bool           `json:"enabled"`
	Next     *float64       `json:"next_due"`
}

func ValidateSchedule(days []string, times, zone, mode string, ns []string) (ScheduleConfig, error) {
	c := ScheduleConfig{Times: unique(strings.Split(times, ",")), Timezone: zone, Mode: mode, Namespaces: unique(ns)}
	bad := func() (ScheduleConfig, error) {
		return c, problem(400, "Välj dagar, 1–4 tider i formatet HH:MM (minst en timme mellan), giltig tidszon och godkända namespaces.")
	}
	for _, d := range unique(days) {
		n, e := strconv.Atoi(d)
		if e != nil || n < 0 || n > 6 || strconv.Itoa(n) != d {
			return bad()
		}
		c.Days = append(c.Days, n)
	}
	sort.Ints(c.Days)
	for i, t := range c.Times {
		c.Times[i] = strings.TrimSpace(t)
	}
	c.Times = unique(c.Times)
	mins := []int{}
	for i, t := range c.Times {
		t = strings.TrimSpace(t)
		point, e := time.Parse("15:04", t)
		if e != nil || point.Format("15:04") != t {
			return bad()
		}
		c.Times[i] = t
		mins = append(mins, point.Hour()*60+point.Minute())
	}
	sort.Ints(mins)
	c.Times = unique(c.Times)
	if len(c.Days) == 0 || len(c.Times) < 1 || len(c.Times) > 4 || len(ns) == 0 || len(ns) > 100 || (mode != "scan" && mode != "report") {
		return bad()
	}
	for _, n := range ns {
		if !NS.MatchString(n) {
			return bad()
		}
	}
	for i, n := range mins {
		if len(mins) > 1 && (mins[(i+1)%len(mins)]-n+1440)%1440 < 60 {
			return bad()
		}
	}
	if zone == "Local" || zone == "" {
		return bad()
	}
	if _, e := time.LoadLocation(zone); e != nil {
		return bad()
	}
	return c, nil
}

// NextDue skips nonexistent local times and selects only the first occurrence
// when clocks turn back, even when after lies between the two occurrences.
func NextDue(c ScheduleConfig, after time.Time) (time.Time, error) {
	loc, e := time.LoadLocation(c.Timezone)
	if e != nil {
		return time.Time{}, e
	}
	local := after.In(loc)
	var best time.Time
	for offset := 0; offset < 9; offset++ {
		day := time.Date(local.Year(), local.Month(), local.Day()+offset, 12, 0, 0, 0, loc)
		weekday := (int(day.Weekday()) + 6) % 7
		allowed := false
		for _, d := range c.Days {
			if d == weekday {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		for _, v := range c.Times {
			point, e := time.Parse("15:04", v)
			if e != nil {
				return time.Time{}, e
			}
			guess := time.Date(day.Year(), day.Month(), day.Day(), point.Hour(), point.Minute(), 0, 0, loc)
			var first time.Time
			for d := -180; d <= 180; d++ {
				candidate := guess.Add(time.Duration(d) * time.Minute)
				p := candidate.In(loc)
				if p.Year() == day.Year() && p.Month() == day.Month() && p.Day() == day.Day() && p.Hour() == point.Hour() && p.Minute() == point.Minute() {
					if first.IsZero() || candidate.Before(first) {
						first = candidate
					}
				}
			}
			if !first.IsZero() && first.After(after) && (best.IsZero() || first.Before(best)) {
				best = first
			}
		}
	}
	if best.IsZero() {
		return best, problem(400, "Ingen giltig schematid hittades inom nästa vecka.")
	}
	return best, nil
}

type Store struct {
	DB          *sql.DB
	PublishLock sync.Mutex
}

func OpenStore(path string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0770); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	for _, q := range []string{
		`PRAGMA busy_timeout=5000`,
		`PRAGMA journal_mode=DELETE`,
		`PRAGMA synchronous=FULL`,
		`CREATE TABLE IF NOT EXISTS schedules (channel_id TEXT PRIMARY KEY,revision INTEGER,config TEXT,enabled INTEGER,next_due REAL,updated_by TEXT,updated_at REAL)`,
		`CREATE TABLE IF NOT EXISTS schedule_runs (id TEXT PRIMARY KEY,channel_id TEXT,revision INTEGER,due REAL,config TEXT,state TEXT,progress TEXT,result TEXT,error TEXT,created REAL,finished REAL,UNIQUE(channel_id,revision,due))`,
		`CREATE TABLE IF NOT EXISTS schedule_audit (channel_id TEXT,revision INTEGER,actor TEXT,config TEXT,enabled INTEGER,changed REAL)`,
		`CREATE TABLE IF NOT EXISTS native_dialogs (id TEXT PRIMARY KEY,created REAL,owner TEXT,channel TEXT,snapshot TEXT,claimed INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS cve_seen (channel_id TEXT,cluster_id TEXT,cve TEXT,reported_at REAL,PRIMARY KEY(channel_id,cluster_id,cve))`,
		`CREATE TABLE IF NOT EXISTS cve_baselines (channel_id TEXT,cluster_id TEXT,namespace TEXT,created_at REAL,PRIMARY KEY(channel_id,cluster_id,namespace))`,
		`UPDATE schedule_runs SET state='interrupted',error='Tjänsten startades om. Leveransen är inte bekräftad.',finished=unixepoch() WHERE state='running'`,
	} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, e
		}
	}
	// An OpenShift upgrade may run under another UID in the same allowed group.
	// Do not chmod an already-correct file owned by the previous UID.
	info, e := os.Stat(path)
	if e == nil && info.Mode().Perm() != 0660 {
		e = os.Chmod(path, 0660)
	}
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func timestamp() float64 { return float64(time.Now().UnixNano()) / 1e9 }
func (s *Store) Schedule(ch string) (*Schedule, error) {
	v := &Schedule{Channel: ch}
	var config string
	var enabled int
	var next sql.NullFloat64
	e := s.DB.QueryRow(`SELECT revision,config,enabled,next_due FROM schedules WHERE channel_id=?`, ch).Scan(&v.Revision, &config, &enabled, &next)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(config), &v.Config); e != nil {
		return nil, e
	}
	v.Enabled = enabled == 1
	if next.Valid {
		v.Next = &next.Float64
	}
	return v, nil
}
func (s *Store) Save(ch, actor string, c ScheduleConfig, enabled bool, expected int) (*Schedule, error) {
	var next any
	if enabled {
		n, e := NextDue(c, time.Now())
		if e != nil {
			return nil, e
		}
		next = float64(n.Unix())
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var rev int
	e = tx.QueryRow(`SELECT revision FROM schedules WHERE channel_id=?`, ch).Scan(&rev)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	if rev != expected {
		return nil, problem(409, "Schemat ändrades. Öppna /cve schedule igen.")
	}
	rev++
	now := timestamp()
	if _, e = tx.Exec(`INSERT OR REPLACE INTO schedules VALUES (?,?,?,?,?,?,?)`, ch, rev, encode(c), enabled, next, actor, now); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(`INSERT INTO schedule_audit VALUES (?,?,?,?,?,?)`, ch, rev, actor, encode(c), enabled, now); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(`UPDATE schedule_runs SET state='cancelled',error='Schema ändrat eller pausat.',finished=? WHERE channel_id=? AND state='queued'`, now, ch); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return s.Schedule(ch)
}

type Run struct {
	ID, Channel string
	Revision    int
	Due         float64
	Config      ScheduleConfig
}

func (s *Store) Enqueue(ch string, revision int) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var config string
	var rev, enabled int
	e = tx.QueryRow(`SELECT config,revision,enabled FROM schedules WHERE channel_id=?`, ch).Scan(&config, &rev, &enabled)
	if e != nil || rev != revision || enabled != 1 {
		return problem(409, "Spara och aktivera det aktuella schemat först.")
	}
	var busy int
	e = tx.QueryRow(`SELECT COUNT(*) FROM schedule_runs WHERE channel_id=? AND (state IN ('queued','running') OR created>?)`, ch, timestamp()-60).Scan(&busy)
	if e != nil {
		return e
	}
	if busy > 0 {
		return problem(429, "En körning pågår eller startades nyss. Vänta minst en minut.")
	}
	now := timestamp()
	_, e = tx.Exec(`INSERT INTO schedule_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)`, token(), ch, rev, now, config, "queued", "Väntar på skannern", "", "", now, nil)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ClaimDue(now float64) error {
	rows, e := s.DB.Query(`SELECT channel_id FROM schedules WHERE enabled=1 AND next_due<=?`, now)
	if e != nil {
		return e
	}
	var channels []string
	for rows.Next() {
		var ch string
		if e = rows.Scan(&ch); e != nil {
			rows.Close()
			return e
		}
		channels = append(channels, ch)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, ch := range channels {
		v, e := s.Schedule(ch)
		if e != nil {
			return e
		}
		if v == nil || !v.Enabled || v.Next == nil {
			continue
		}
		next, e := NextDue(v.Config, time.Unix(int64(now), 0))
		if e != nil {
			return e
		}
		state := "queued"
		var finished any
		reason := ""
		if now-*v.Next > 300 {
			state = "missed"
			finished = now
			reason = "Tjänsten var inte tillgänglig i tid."
		}
		tx, e := s.DB.Begin()
		if e != nil {
			return e
		}
		_, e = tx.Exec(`INSERT OR IGNORE INTO schedule_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)`, token(), ch, v.Revision, *v.Next, encode(v.Config), state, "Väntar på skannern", "", reason, now, finished)
		if e == nil {
			_, e = tx.Exec(`UPDATE schedules SET next_due=? WHERE channel_id=? AND revision=?`, next.Unix(), ch, v.Revision)
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	if _, e = s.DB.Exec(`UPDATE schedule_runs SET state='missed',error='Skannern var upptagen för länge.',finished=? WHERE state='queued' AND due<?`, now, now-300); e != nil {
		return e
	}
	_, e = s.DB.Exec(`DELETE FROM schedule_runs WHERE created<?`, now-30*86400)
	return e
}
func (s *Store) TakeRun() (*Run, error) {
	tx, e := s.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r := &Run{}
	var config string
	e = tx.QueryRow(`SELECT id,channel_id,revision,due,config FROM schedule_runs WHERE state='queued' ORDER BY due LIMIT 1`).Scan(&r.ID, &r.Channel, &r.Revision, &r.Due, &config)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(config), &r.Config); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(`UPDATE schedule_runs SET state='running' WHERE id=? AND state='queued'`, r.ID); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return r, nil
}
func (s *Store) Finish(id, state string, result M, reason string) error {
	_, e := s.DB.Exec(`UPDATE schedule_runs SET state=?,result=?,error=?,finished=? WHERE id=?`, state, encode(result), reason, timestamp(), id)
	return e
}
func (s *Store) History(ch string) (string, error) {
	rows, e := s.DB.Query(`SELECT due,state FROM schedule_runs WHERE channel_id=? ORDER BY created DESC LIMIT 5`, ch)
	if e != nil {
		return "", e
	}
	defer rows.Close()
	text := "**ACS · Senaste körningar**\n"
	names := map[string]string{"queued": "Väntar", "running": "Pågår", "done": "Levererad", "partial": "Levererad med luckor", "failed": "Misslyckad", "missed": "Missad", "cancelled": "Avbruten", "interrupted": "Avbruten vid omstart"}
	for rows.Next() {
		var due float64
		var state string
		if e = rows.Scan(&due, &state); e != nil {
			return "", e
		}
		text += "• " + time.Unix(int64(due), 0).UTC().Format("2006-01-02 15:04 UTC") + " · " + names[state] + "\n"
	}
	return text, rows.Err()
}

// Publish serializes first-seen detection and only records it after an
// acknowledged post. Delivery has an unavoidable crash window; see operations.
func (s *Store) Publish(ctx context.Context, svc *Services, ch string, r M) (string, error) {
	s.PublishLock.Lock()
	defer s.PublishLock.Unlock()
	cluster := svc.C.Get("STACKROX_CLUSTER_ID", "")
	seen := map[string]bool{}
	baseline := map[string]bool{}
	rows, e := s.DB.Query(`SELECT cve FROM cve_seen WHERE channel_id=? AND cluster_id=?`, ch, cluster)
	if e != nil {
		return "", e
	}
	for rows.Next() {
		var v string
		if e = rows.Scan(&v); e != nil {
			rows.Close()
			return "", e
		}
		seen[v] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return "", e
	}
	rows, e = s.DB.Query(`SELECT namespace FROM cve_baselines WHERE channel_id=? AND cluster_id=?`, ch, cluster)
	if e != nil {
		return "", e
	}
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			rows.Close()
			return "", e
		}
		baseline[n] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return "", e
	}
	observed := map[string]bool{}
	newCves, alertCves := []string{}, []string{}
	first := svc.C.Flag("CVE_ALERT_FIRST_REPORT", false)
	for _, v := range arr(r["rows"]) {
		row := obj(v)
		cve := str(row["cve"])
		if !CVE.MatchString(cve) {
			continue
		}
		observed[cve] = true
		if !seen[cve] && (first || baseline[str(row["namespace"])]) {
			newCves = append(newCves, cve)
			if svc.C.Flag("CVE_ALERTS_ENABLED", true) && score(row) >= svc.C.Float("CVE_ALERT_MIN_CVSS", 9) {
				alertCves = append(alertCves, cve)
			}
		}
	}
	r["newCves"] = unique(newCves)
	r["alertCves"] = unique(alertCves)
	covered := false
	for _, ns := range stringsOf(r["namespaces"]) {
		covered = covered || baseline[ns]
	}
	r["alertBaseline"] = !first && !covered
	id, e := svc.Post(ctx, ch, r)
	if e != nil {
		return "", e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	for cve := range observed {
		if _, e = tx.Exec(`INSERT OR IGNORE INTO cve_seen VALUES (?,?,?,?)`, ch, cluster, cve, timestamp()); e != nil {
			return "", e
		}
	}
	if !incomplete(r) {
		for _, ns := range stringsOf(r["namespaces"]) {
			if _, e = tx.Exec(`INSERT OR IGNORE INTO cve_baselines VALUES (?,?,?,?)`, ch, cluster, ns, timestamp()); e != nil {
				return "", e
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	return id, nil
}
func message(err error) string {
	var p *Problem
	if errors.As(err, &p) {
		return p.Message
	}
	return "Åtgärden misslyckades. Kontrollera tjänstens driftstatus."
}
func (s Schedule) Result() M {
	return M{"kind": "schedule", "config": s.Config, "enabled": s.Enabled, "revision": s.Revision, "next_due": s.Next}
}
func (s *Store) Close() error   { return s.DB.Close() }
func (s *Store) String() string { return fmt.Sprintf("SQLite state") }
