package bridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

const callbackID = "cvebridge.schedule"

type Snapshot struct {
	Account    string   `json:"account"`
	Candidates []string `json:"candidates"`
	Members    []string `json:"members"`
	Policy     string   `json:"policy"`
	Revision   int      `json:"revision"`
}

func jsonSchedule(v any) (ScheduleConfig, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return ScheduleConfig{}, e
	}
	var c ScheduleConfig
	e = json.Unmarshal(b, &c)
	return c, e
}
func (a *App) DialogContext(ctx context.Context, owner, ch string) (*Schedule, Snapshot, error) {
	snap := Snapshot{}
	if len(a.S.C.ScheduleScopes[ch]) == 0 {
		return nil, snap, problem(403, "Kanalen är inte godkänd för scheman.")
	}
	if managers := a.S.C.Managers[ch]; len(managers) > 0 && !has(managers, owner) {
		return nil, snap, problem(403, "Du är inte utsedd att ändra kanalens schema.")
	}
	user, e := a.S.User(ctx, owner)
	if e != nil {
		return nil, snap, e
	}
	actor, e := a.S.ActorAudience(ctx, owner, ch, nil)
	if e != nil {
		return nil, snap, e
	}
	audience, e := a.S.ScheduledAudience(ctx, ch, nil)
	if e != nil {
		return nil, snap, e
	}
	current, e := a.Store.Schedule(ch)
	if e != nil {
		return nil, snap, e
	}
	existing := []string{}
	rev := 0
	if current != nil {
		existing = current.Config.Namespaces
		rev = current.Revision
	}
	snap = Snapshot{Account: user, Candidates: intersect(append(actor.Namespaces, existing...), audience.Namespaces), Members: audience.Members, Policy: audience.Policy, Revision: rev}
	if len(snap.Candidates) == 0 {
		return nil, snap, problem(403, "Inga namespaces är godkända för teamet och rapporttjänsten.")
	}
	return current, snap, nil
}
func selectElement(name, label string, values, labels []string, defaultValue string, multi bool) M {
	opts := []any{}
	for i, v := range values {
		opts = append(opts, M{"value": v, "text": labels[i]})
	}
	m := M{"name": name, "display_name": label, "type": "select", "options": opts, "default": defaultValue}
	if multi {
		m["multiselect"] = true
	}
	return m
}
func (a *App) OpenDialog(ctx context.Context, owner, ch, trigger string) error {
	if len(trigger) < 1 || len(trigger) > 512 {
		return problem(400, "Kör /cve schedule igen för att öppna formuläret.")
	}
	if a.S.C.Get("MATTERMOST_DIALOG_URL", "") == "" {
		return problem(503, "MATTERMOST_DIALOG_URL saknas.")
	}
	_, e := a.Store.DB.Exec(`DELETE FROM native_dialogs WHERE created<?`, timestamp()-600)
	if e != nil {
		return e
	}
	var count int
	if e = a.Store.DB.QueryRow(`SELECT COUNT(*) FROM native_dialogs WHERE owner=? AND created>?`, owner, timestamp()-60).Scan(&count); e != nil {
		return e
	}
	if count >= 20 {
		return problem(429, "För många formulär. Vänta en minut.")
	}
	current, snap, e := a.DialogContext(ctx, owner, ch)
	if e != nil {
		return e
	}
	key := token()
	_, e = a.Store.DB.Exec(`INSERT INTO native_dialogs(id,created,owner,channel,snapshot) VALUES (?,?,?,?,?)`, key, timestamp(), owner, ch, encode(snap))
	if e != nil {
		return e
	}
	c := ScheduleConfig{Days: []int{0, 1, 2, 3, 4, 5, 6}, Times: []string{"08:00"}, Timezone: a.S.C.Get("SCHEDULE_DEFAULT_TIMEZONE", "Europe/Stockholm"), Mode: "scan", Namespaces: snap.Candidates}
	enabled := "yes"
	actions, labels := []string{"save"}, []string{"Spara inställningar"}
	if current != nil {
		c = current.Config
		if !current.Enabled {
			enabled = "no"
		}
		actions = append(actions, "pause", "run", "history")
		labels = append(labels, "Pausa sparat schema", "Provkör sparat schema", "Visa körhistorik")
	}
	days := []string{}
	for _, d := range c.Days {
		days = append(days, string(rune('0'+d)))
	}
	dialog := M{"callback_id": callbackID, "title": "Teamets schema", "state": key, "introduction_text": "Välj dagar, tider och namespaces. Spara för att börja köra automatiskt.", "submit_label": "Utför", "notify_on_cancel": true, "elements": []any{
		selectElement("days", "Veckodagar", []string{"0", "1", "2", "3", "4", "5", "6"}, Days, strings.Join(days, ","), true),
		M{"name": "times", "display_name": "Tider", "type": "text", "default": strings.Join(c.Times, ", "), "help_text": "HH:MM, högst fyra tider, minst en timme mellan."},
		M{"name": "timezone", "display_name": "Tidszon", "type": "text", "default": c.Timezone},
		selectElement("namespaces", "Namespaces", snap.Candidates, snap.Candidates, strings.Join(c.Namespaces, ","), true),
		selectElement("mode", "Vad ska göras?", []string{"scan", "report"}, []string{"Ny skanning och rapport", "Rapport från befintliga fynd"}, c.Mode, false),
		selectElement("enabled", "Efter sparning", []string{"yes", "no"}, []string{"Aktiverat", "Pausat"}, enabled, false), selectElement("action", "Åtgärd", actions, labels, "save", false)}}
	_, e = a.S.MMRequest(ctx, "/api/v4/actions/dialogs/open", M{"trigger_id": trigger, "url": strings.TrimRight(a.S.C.Get("MATTERMOST_DIALOG_URL", ""), "/") + "/" + key, "dialog": dialog})
	if e != nil {
		_, _ = a.Store.DB.Exec(`DELETE FROM native_dialogs WHERE id=?`, key)
	}
	return e
}
func multiple(v any) ([]string, error) {
	if s, ok := v.(string); ok {
		if s == "" {
			return []string{}, nil
		}
		return strings.Split(s, ","), nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, problem(400, "Välj giltiga dagar och namespaces.")
	}
	out := []string{}
	for _, v := range a {
		s, ok := v.(string)
		if !ok {
			return nil, problem(400, "Välj giltiga fält.")
		}
		out = append(out, s)
	}
	return out, nil
}
func (a *App) SubmitDialog(ctx context.Context, key string, p M) (err error) {
	var owner, ch, snapshot string
	e := a.Store.DB.QueryRow(`SELECT owner,channel,snapshot FROM native_dialogs WHERE id=? AND created>?`, key, timestamp()-600).Scan(&owner, &ch, &snapshot)
	if errors.Is(e, sql.ErrNoRows) {
		return problem(404, "Formuläret har gått ut. Kör /cve schedule igen.")
	}
	if e != nil {
		return e
	}
	if str(p["type"]) != "dialog_submission" || str(p["callback_id"]) != callbackID || !equal(str(p["state"]), key) || str(p["user_id"]) != owner || str(p["channel_id"]) != ch {
		return problem(403, "Formulärets avsändare eller kanal kunde inte verifieras.")
	}
	result, e := a.Store.DB.Exec(`UPDATE native_dialogs SET claimed=1 WHERE id=? AND claimed=0`, key)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return problem(409, "Formuläret behandlas redan.")
	}
	completed := false
	defer func() {
		if completed {
			_, _ = a.Store.DB.Exec(`DELETE FROM native_dialogs WHERE id=?`, key)
		} else {
			_, _ = a.Store.DB.Exec(`UPDATE native_dialogs SET claimed=0 WHERE id=?`, key)
		}
	}()
	if boolean(p["cancelled"]) {
		completed = true
		return nil
	}
	current, fresh, e := a.DialogContext(ctx, owner, ch)
	if e != nil {
		return e
	}
	var saved Snapshot
	if e = json.Unmarshal([]byte(snapshot), &saved); e != nil {
		return e
	}
	if saved.Account != fresh.Account || saved.Policy != fresh.Policy || !same(saved.Members, fresh.Members) {
		return problem(403, "Identitet eller kanalbehörigheter ändrades. Öppna formuläret igen.")
	}
	if saved.Revision != fresh.Revision {
		return problem(409, "Schemat ändrades. Öppna /cve schedule igen.")
	}
	form, ok := p["submission"].(map[string]any)
	if !ok {
		return problem(400, "Formuläret kunde inte läsas.")
	}
	var changed *Schedule
	switch str(form["action"]) {
	case "save":
		for _, k := range []string{"times", "timezone", "mode", "enabled"} {
			v, ok := form[k].(string)
			if !ok || len(v) > 256 {
				return problem(400, "Kontrollera formulärets fält.")
			}
		}
		enabled := str(form["enabled"])
		if enabled != "yes" && enabled != "no" {
			return problem(400, "Välj aktiverat eller pausat.")
		}
		days, e := multiple(form["days"])
		if e != nil {
			return e
		}
		ns, e := multiple(form["namespaces"])
		if e != nil {
			return e
		}
		c, e := ValidateSchedule(days, str(form["times"]), str(form["timezone"]), str(form["mode"]), ns)
		if e != nil {
			return e
		}
		if len(intersect(c.Namespaces, intersect(saved.Candidates, fresh.Candidates))) != len(c.Namespaces) {
			return problem(403, "Valda namespaces är inte godkända.")
		}
		c.Policy = fresh.Policy
		changed, e = a.Store.Save(ch, owner, c, enabled == "yes", saved.Revision)
		if e != nil {
			return e
		}
	case "pause":
		if current == nil {
			return problem(400, "Spara ett schema först.")
		}
		changed, e = a.Store.Save(ch, owner, current.Config, false, saved.Revision)
		if e != nil {
			return e
		}
	case "run":
		if current == nil {
			return problem(400, "Spara ett schema först.")
		}
		if _, e = a.S.ScheduledAudience(ctx, ch, current.Config.Namespaces); e != nil {
			return e
		}
		if e = a.Store.Enqueue(ch, saved.Revision); e != nil {
			return e
		}
		completed = true
		a.S.Notice(ctx, owner, ch, "**ACS · Provkörning köad**\nDet sparade schemat används. Rapporten kommer i kanalen.")
		a.Wake()
		return nil
	case "history":
		if current == nil {
			return problem(400, "Spara ett schema först.")
		}
		text, e := a.Store.History(ch)
		if e != nil {
			return e
		}
		completed = true
		a.S.Notice(ctx, owner, ch, text)
		return nil
	default:
		return problem(400, "Välj en giltig åtgärd.")
	}
	completed = true
	if _, e = a.S.Post(ctx, ch, changed.Result()); e != nil {
		a.S.Notice(ctx, owner, ch, "**ACS · Schemat är sparat**\nKanalbekräftelsen kunde inte levereras. Kör /cve schedule för att kontrollera.")
	}
	return nil
}
