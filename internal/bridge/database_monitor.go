package bridge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const databaseCheckInterval = time.Hour
const databaseReportInterval = 24 * time.Hour
const databaseRetryInterval = 5 * time.Minute

// The database monitor is independent of the image scan worker. A long scan
// must not delay an operational freshness check. Loop stops before Wait runs.
func (a *App) startDatabaseMonitor(now time.Time) {
	if a.S.C.Get("DATABASE_MONITOR_CHANNEL_ID", "") == "" || a.ctx.Err() != nil || !a.monitor.TryLock() {
		return
	}
	if now.Before(a.monitorNext) {
		a.monitor.Unlock()
		return
	}
	a.monitorNext = now.Add(databaseCheckInterval)
	a.tasks.Add(1)
	go func() {
		defer a.tasks.Done()
		defer a.monitor.Unlock()
		ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
		defer cancel()
		if e := a.checkDatabaseMonitor(ctx, now); e != nil {
			a.S.acsInfo("monitor_retry_scheduled", M{"retry_after_minutes": int(databaseRetryInterval / time.Minute)})
			a.monitorNext = time.Now().Add(databaseRetryInterval)
		}
	}()
}

// A configured ops channel receives only scanner database metadata. It does
// not gain access to namespace reports, image results or slash commands.
func (s *Services) databaseMonitorDestination(ctx context.Context, ch string) error {
	if ch == "" || ch != s.C.Get("DATABASE_MONITOR_CHANNEL_ID", "") || !ID.MatchString(ch) {
		return problem(403, "Driftkanalen är inte godkänd för databasbevakning.")
	}
	bot, e := s.Bot(ctx)
	if e != nil {
		return e
	}
	channel, e := s.MMRequest(ctx, "/api/v4/channels/"+ch, nil)
	if e != nil {
		return e
	}
	if str(channel["id"]) != ch || str(channel["type"]) != "P" || num(channel["delete_at"]) != 0 {
		return problem(403, "Databasbevakning kräver en aktiv privat driftkanal.")
	}
	member, e := s.MMRequest(ctx, "/api/v4/channels/"+ch+"/members/"+bot, nil)
	if e != nil {
		return e
	}
	if str(member["channel_id"]) != ch || str(member["user_id"]) != bot {
		return problem(403, "Boten måste vara medlem i driftkanalen.")
	}
	return nil
}

// Only successful deliveries advance the persisted notification state. This
// survives pod restarts on the same PVC. Like other posts, a crash between the
// Mattermost acknowledgement and the SQLite commit can cause a duplicate.
func (a *App) checkDatabaseMonitor(ctx context.Context, now time.Time) (err error) {
	ch := a.S.C.Get("DATABASE_MONITOR_CHANNEL_ID", "")
	if ch == "" {
		return nil
	}
	a.S.acsInfo("monitor_check_start", M{"component": a.S.C.Get("STACKROX_SCANNER_COMPONENT", "SCANNER")})
	stage := "state_read"
	defer func() {
		if err != nil {
			reason := "state_unavailable"
			if stage != "state_read" && stage != "state_write" {
				// Mattermost errors are already sanitized by the API wrapper.
				reason = message(err)
			}
			a.S.acsInfo("monitor_check_failed", M{"stage": stage, "reason": reason})
		}
	}()
	identity := []string{strings.TrimRight(a.S.C.Get("STACKROX_URL", ""), "/"), a.S.C.Get("STACKROX_SCANNER_COMPONENT", "SCANNER"), ch}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(encode(identity))))
	var previous string
	var notified int64
	e := a.Store.DB.QueryRowContext(ctx, `SELECT state,notified_at FROM database_monitor WHERE monitor_key=?`, key).Scan(&previous, &notified)
	initial := errors.Is(e, sql.ErrNoRows)
	if e != nil && !initial {
		return e
	}
	if !initial && (notified <= 0 || (previous != "recent" && previous != "stale" && previous != "unknown")) {
		return problem(503, "Databasbevakningens sparade status är ogiltig.")
	}
	// Leave time to deliver an unknown-status alert even if Central hangs.
	a.S.acsInfo("monitor_acs_start", M{
		"endpoint":                acsEndpoint(strings.TrimRight(a.S.C.Get("STACKROX_URL", ""), "/") + "/v1/integrationhealth/vulndefinitions"),
		"component":               a.S.C.Get("STACKROX_SCANNER_COMPONENT", "SCANNER"),
		"status_token_configured": a.S.C.Get("STACKROX_STATUS_TOKEN", "") != "",
	})
	probe, cancel := context.WithTimeout(ctx, 75*time.Second)
	result := a.S.databaseStatusAt(probe, now)
	cancel()
	state := str(result["state"])
	a.S.acsInfo("monitor_acs_complete", M{"state": state, "reason": str(result["reason"]), "last_updated": str(result["lastUpdated"])})
	last := time.Unix(notified, 0)
	if !initial && state == previous && !now.Before(last) && now.Sub(last) < databaseReportInterval {
		a.S.acsInfo("monitor_post_skipped", M{"state": state, "reason": "unchanged_within_24_hours"})
		return nil
	}
	stage = "mattermost_destination"
	a.S.acsInfo("monitor_destination_check_start", M{})
	if e = a.S.databaseMonitorDestination(ctx, ch); e != nil {
		return e
	}
	result["kind"] = "database_monitor"
	result["recovered"] = !initial && previous != "recent" && state == "recent"
	stage = "mattermost_post"
	a.S.acsInfo("monitor_post_start", M{"state": state})
	if _, e = a.S.Post(ctx, ch, result); e != nil {
		return e
	}
	a.S.acsInfo("monitor_post_sent", M{"state": state})
	stage = "state_write"
	_, e = a.Store.DB.ExecContext(ctx, `INSERT INTO database_monitor (monitor_key,state,notified_at) VALUES (?,?,?) ON CONFLICT(monitor_key) DO UPDATE SET state=excluded.state,notified_at=excluded.notified_at`, key, state, now.Unix())
	if e == nil {
		a.S.acsInfo("monitor_check_complete", M{"state": state, "next_check_after_minutes": int(databaseCheckInterval / time.Minute)})
	}
	return e
}

func databaseMonitorMessage(r M) M {
	title, color := "CVE-databasens status kan inte verifieras", "#D97732"
	action := "Kontrollera anslutning, certifikat, att vald Scanner är aktiv och att ACS-token har Administration: Read."
	switch str(r["state"]) {
	case "recent":
		title, color = "CVE-databasen är inom åldersgränsen", "#329C89"
		if boolean(r["recovered"]) {
			title = "CVE-databasen är inom gränsen igen"
		}
		action = "Ingen åtgärd behövs för databasens ålder."
	case "stale":
		title, color = "CVE-databasen är för gammal", "#D64550"
		action = "Kontrollera definitionshämtningen i ACS Central och databasuppdateringen i Scanner. I offline-miljö: kontrollera senaste importen."
	}
	updated, age := "okänd", "okänd"
	if str(r["lastUpdated"]) != "" {
		updated = inert(str(r["lastUpdated"]), 40)
		age = fmt.Sprintf("%.1f timmar", num(r["ageHours"]))
	}
	text := fmt.Sprintf("**Scanner:** %s\n**Senast uppdaterad:** %s\n**Ålder:** %s · gräns %g timmar\n**Kontrollerad:** %s", inert(str(r["component"]), 24), updated, age, num(r["maxAgeHours"]), inert(str(r["checkedAt"]), 40))
	if reason := str(r["reason"]); reason != "" {
		text += "\n**Orsak:** " + inert(reason, 200)
	}
	text += "\n\n**Åtgärd:** " + action + "\nKontroll varje timme · status var 24:e timme samt vid ändrat läge."
	return card(title, text, "**ACS · Driftbevakning av CVE-databasen**", color)
}
