package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type App struct {
	S      *Services
	Store  *Store
	worker sync.Mutex
	wake   chan struct{}
	ctx    context.Context
	tasks  sync.WaitGroup
}

func NewApp(ctx context.Context, s *Services, store *Store) *App {
	return &App{S: s, Store: store, wake: make(chan struct{}, 1), ctx: ctx}
}
func (a *App) Wake() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}
func (a *App) Loop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	a.Wake()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.tick()
		case <-a.wake:
			a.tick()
		}
	}
}
func (a *App) Wait() { a.tasks.Wait() }
func (a *App) tick() {
	if e := a.Store.ClaimDue(timestamp()); e != nil {
		log.Print("scheduler state unavailable")
		return
	}
	if !a.worker.TryLock() {
		return
	}
	r, e := a.Store.TakeRun()
	if e != nil || r == nil {
		a.worker.Unlock()
		return
	}
	a.tasks.Add(1)
	go func() {
		defer a.tasks.Done()
		defer a.worker.Unlock()
		a.execute(r.Channel, "", r.Config.Mode, r.Config.Namespaces, r)
	}()
}
func (a *App) execute(ch, owner, command string, ns []string, run *Run) {
	ctx, cancel := context.WithTimeout(a.ctx, 35*time.Minute)
	defer cancel()
	var initial *Audience
	authorize := func() error {
		var fresh Audience
		var e error
		if run != nil {
			current, err := a.Store.Schedule(ch)
			if err != nil {
				return err
			}
			if current == nil || !current.Enabled || current.Revision != run.Revision {
				return problem(403, "Schemat ändrades eller pausades. Inga nya resultat publiceras.")
			}
			fresh, e = a.S.ScheduledAudience(ctx, ch, ns)
			if e == nil && fresh.Policy != run.Config.Policy {
				e = problem(403, "Delningspolicyn har ändrats. Spara schemat igen.")
			}
		} else {
			fresh, e = a.S.ActorAudience(ctx, owner, ch, ns)
		}
		if e != nil {
			return e
		}
		if initial != nil && !same(*initial, fresh) {
			return problem(403, "Kanalmedlemmar eller behörigheter ändrades under körningen.")
		}
		initial = &fresh
		ns = fresh.Namespaces
		return nil
	}
	err := authorize()
	var result M
	if err == nil {
		switch command {
		case "scan", "report":
			result, err = a.S.Scan(ctx, ns, authorize, command == "scan", run != nil)
		case "status":
			result = a.S.DatabaseStatus(ctx)
		default:
			result, err = a.S.Lookup(ctx, command, ns, authorize)
		}
	}
	if err == nil {
		result["sharingPolicy"] = initial.Policy
		if run != nil {
			result["scheduled"] = true
		}
		err = authorize()
	}
	if err == nil && (str(result["kind"]) == "scan" || str(result["kind"]) == "lookup") {
		var files []string
		files, err = a.S.Upload(ctx, ch, result)
		result["reportFileIds"] = files
		if err == nil {
			err = authorize()
		}
	}
	var post string
	if err == nil {
		if str(result["kind"]) == "scan" {
			post, err = a.Store.Publish(ctx, a.S, ch, result)
		} else {
			post, err = a.S.Post(ctx, ch, result)
		}
	}
	if err != nil {
		log.Print("run failed: " + message(err))
		if run != nil {
			if e := a.Store.Finish(run.ID, "failed", nil, message(err)); e != nil {
				log.Print("run state could not be saved")
			}
			if authorize() == nil {
				_, _ = a.S.Post(ctx, ch, M{"kind": "schedule_error"})
			}
		} else {
			a.S.Notice(ctx, owner, ch, "**ACS · Körningen misslyckades**\n"+message(err))
		}
		return
	}
	if run != nil {
		state := "done"
		if incomplete(result) {
			state = "partial"
		}
		if e := a.Store.Finish(run.ID, state, M{"post_id": post, "scannedImages": result["scannedImages"], "findings": len(arr(result["rows"])), "namespaces": ns}, ""); e != nil {
			log.Print("delivered run state could not be saved")
		}
	}
}
func verifyCommandToken(expected string, header string, form string) bool {
	if expected == "" {
		return false
	}
	candidates := []string{}
	if header != "" {
		parts := strings.Fields(header)
		if len(parts) != 2 || (parts[0] != "Token" && parts[0] != "Bearer") {
			return false
		}
		candidates = append(candidates, parts[1])
	}
	if form != "" {
		candidates = append(candidates, form)
	}
	if len(candidates) == 0 {
		return false
	}
	ok := true
	for _, c := range candidates {
		ok = equal(c, expected) && ok
	}
	return ok
}

var dialogPath = regexp.MustCompile(`^/slash/cve/dialog/([A-Za-z0-9_-]{43})$`)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func reply(w http.ResponseWriter, v M) {
	v["response_type"] = "ephemeral"
	v["username"] = "ACS"
	writeJSON(w, 200, v)
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		writeJSON(w, 200, M{"status": "ok", "runtime": "go"})
		return
	}
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	if match := dialogPath.FindStringSubmatch(r.URL.Path); match != nil {
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
		var p M
		if e != nil || json.Unmarshal(b, &p) != nil || p == nil {
			writeJSON(w, 400, M{"error": "Ogiltigt formulär."})
			return
		}
		e = a.SubmitDialog(r.Context(), match[1], p)
		if e != nil {
			status := 200
			var p *Problem
			if errors.As(e, &p) && (p.Status == 401 || p.Status == 403) {
				status = p.Status
			}
			writeJSON(w, status, M{"error": message(e)})
			return
		}
		writeJSON(w, 200, M{})
		return
	}
	if r.URL.Path != "/slash/cve" && r.URL.Path != "/slash/acs" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if e := r.ParseForm(); e != nil {
		writeJSON(w, 400, M{"error": "Förfrågan är för stor eller ogiltig."})
		return
	}
	f := r.PostForm
	expected := a.S.C.Get("MATTERMOST_COMMAND_TOKEN", "")
	if f.Get("command") == "/acs" && a.S.C.Get("MATTERMOST_ACS_COMMAND_TOKEN", "") != "" {
		expected = a.S.C.Get("MATTERMOST_ACS_COMMAND_TOKEN", "")
	}
	if !verifyCommandToken(expected, r.Header.Get("Authorization"), f.Get("token")) {
		writeJSON(w, 401, M{"error": "Kommandot kunde inte verifieras."})
		return
	}
	if cmd := f.Get("command"); cmd != "/cve" && cmd != "/acs" {
		reply(w, ErrorMessage(problem(400, "Använd /cve eller /acs.")))
		return
	}
	args := strings.Fields(f.Get("text"))
	if len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "hjälp")) {
		reply(w, HelpMessage())
		return
	}
	command := strings.ToLower(args[0])
	if command != "scan" && command != "report" && command != "status" && command != "schedule" {
		command = strings.ToUpper(args[0])
		if !CVE.MatchString(command) {
			reply(w, ErrorMessage(problem(400, "Använd /cve help för giltiga kommandon.")))
			return
		}
	}
	if len(args) > 2 || ((command == "status" || command == "schedule") && len(args) != 1) {
		reply(w, ErrorMessage(problem(400, "Kontrollera argumenten med /cve help.")))
		return
	}
	ns := []string{}
	if len(args) == 2 {
		if !NS.MatchString(args[1]) {
			reply(w, ErrorMessage(problem(400, "Ogiltigt namespace.")))
			return
		}
		ns = append(ns, args[1])
	}
	owner, ch := f.Get("user_id"), f.Get("channel_id")
	if !ID.MatchString(owner) || len(a.S.C.Scopes[ch]) == 0 {
		reply(w, ErrorMessage(problem(403, "Kör kommandot i en godkänd privat teamkanal.")))
		return
	}
	if command == "schedule" {
		if e := a.OpenDialog(r.Context(), owner, ch, f.Get("trigger_id")); e != nil {
			reply(w, ErrorMessage(e))
			return
		}
		reply(w, M{"text": "Schemaformuläret öppnas här i Mattermost."})
		return
	}
	if !a.worker.TryLock() {
		reply(w, ErrorMessage(problem(409, "En körning pågår. Försök igen när den är klar.")))
		return
	}
	a.tasks.Add(1)
	go func() { defer a.tasks.Done(); defer a.worker.Unlock(); a.execute(ch, owner, command, ns, nil) }()
	reply(w, card("Körningen är köad", "Behörigheterna kontrolleras före körningen. Rapporten kommer i den här kanalen. Eventuella fel visas privat för dig.", "**ACS · Beställning mottagen**", "#438D9A"))
}
