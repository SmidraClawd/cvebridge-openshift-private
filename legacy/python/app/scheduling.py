"""Persistent team schedules with explicit local times and bounded execution.

SQLite is shared with command state. One application replica owns the worker;
atomic due-slot claims survive restarts without replaying delivered reports.
"""
from datetime import datetime, timedelta, timezone
import json
import logging
import secrets
import threading
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

LOG = logging.getLogger("cvebridge.schedule")
DAY_NAMES = ["Måndag", "Tisdag", "Onsdag", "Torsdag", "Fredag", "Lördag", "Söndag"]


class ScheduleError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def validate_config(days, times, zone, mode, namespaces):
    try:
        if any(str(d) not in {str(i) for i in range(7)} for d in days):
            raise ValueError()
        days = sorted({int(d) for d in days})
        times = sorted(set(t.strip() for t in times.split(",")))
        if not days or not 1 <= len(times) <= 4:
            raise ValueError()
        minutes = []
        for value in times:
            point = datetime.strptime(value, "%H:%M")
            if point.strftime("%H:%M") != value:
                raise ValueError()
            minutes.append(point.hour*60+point.minute)
        if len(minutes) > 1 and min((b-a) % 1440 for a,b in zip(minutes, minutes[1:]+minutes[:1])) < 60:
            raise ValueError()
        ZoneInfo(zone)
        if mode not in {"scan", "report"} or not namespaces or len(namespaces) > 100:
            raise ValueError()
    except (ValueError, TypeError, AttributeError, ZoneInfoNotFoundError):
        raise ScheduleError(400, "Välj dagar, 1–4 tider i formatet HH:MM (minst en timme mellan), giltig tidszon och minst ett godkänt namespace.") from None
    return {"days": days, "times": times, "timezone": zone, "mode": mode, "namespaces": sorted(set(namespaces))}


def next_due(config, after):
    """UTC timestamp of the next slot. Skip missing DST times; use first fold."""
    zone = ZoneInfo(config["timezone"])
    local = datetime.fromtimestamp(after, timezone.utc).astimezone(zone)
    candidates = []
    for offset in range(9):
        day = local.date()+timedelta(days=offset)
        if day.weekday() not in config["days"]:
            continue
        for value in config["times"]:
            hour, minute = map(int, value.split(":"))
            point = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone, fold=0)
            stamp = point.timestamp()
            returned = datetime.fromtimestamp(stamp, timezone.utc).astimezone(zone)
            if (returned.date(), returned.hour, returned.minute) != (day, hour, minute):
                continue
            if stamp > after:
                candidates.append(stamp)
    if not candidates:
        raise ScheduleError(400, "Ingen giltig schematid hittades inom nästa vecka.")
    return min(candidates)


class Schedules:
    def __init__(self, store):
        self.store = store
        with store.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS schedules (channel_id TEXT PRIMARY KEY, revision INTEGER, config TEXT, enabled INTEGER, next_due REAL, updated_by TEXT, updated_at REAL)")
            db.execute("CREATE TABLE IF NOT EXISTS schedule_runs (id TEXT PRIMARY KEY, channel_id TEXT, revision INTEGER, due REAL, config TEXT, state TEXT, progress TEXT, result TEXT, error TEXT, created REAL, finished REAL, UNIQUE(channel_id,revision,due))")
            db.execute("CREATE TABLE IF NOT EXISTS schedule_audit (channel_id TEXT, revision INTEGER, actor TEXT, config TEXT, enabled INTEGER, changed REAL)")

    def get(self, channel_id):
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM schedules WHERE channel_id=?", (channel_id,)).fetchone()
        if not row:
            return None
        row = dict(row)
        row["config"] = json.loads(row["config"])
        return row

    def save(self, channel_id, config, enabled, actor, expected_revision, now=None):
        now = time.time() if now is None else now
        due = next_due(config, now) if enabled else None
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT revision FROM schedules WHERE channel_id=?", (channel_id,)).fetchone()
            revision = previous["revision"] if previous else 0
            if revision != expected_revision:
                raise ScheduleError(409, "Någon har ändrat schemat. Kör /cve schedule igen för aktuella inställningar.")
            revision += 1
            encoded = json.dumps(config)
            db.execute("INSERT OR REPLACE INTO schedules VALUES (?,?,?,?,?,?,?)", (channel_id, revision, encoded, int(enabled), due, actor, now))
            db.execute("INSERT INTO schedule_audit VALUES (?,?,?,?,?,?)", (channel_id, revision, actor, encoded, int(enabled), now))
            db.execute("UPDATE schedule_runs SET state='cancelled',error='Schema ändrat eller pausat.',finished=? WHERE channel_id=? AND state='queued'", (now, channel_id))
        return self.get(channel_id)

    def history(self, channel_id):
        with self.store.connect() as db:
            rows = db.execute("SELECT id,revision,state,progress,error,due,finished,result FROM schedule_runs WHERE channel_id=? ORDER BY created DESC LIMIT 10", (channel_id,)).fetchall()
        return [dict(row) for row in rows]

    def enqueue_now(self, channel_id, revision, now=None):
        now = time.time() if now is None else now
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM schedules WHERE channel_id=?", (channel_id,)).fetchone()
            if not row or not row["enabled"] or row["revision"] != revision:
                raise ScheduleError(409, "Spara och aktivera det aktuella schemat först.")
            busy = db.execute("SELECT 1 FROM schedule_runs WHERE channel_id=? AND state IN ('queued','running')", (channel_id,)).fetchone()
            recent = db.execute("SELECT 1 FROM schedule_runs WHERE channel_id=? AND created>?", (channel_id, now-60)).fetchone()
            if busy or recent:
                raise ScheduleError(429, "En körning pågår eller startades nyss. Vänta minst en minut.")
            run_id = secrets.token_urlsafe(24)
            db.execute("INSERT INTO schedule_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)", (run_id, channel_id, revision, now, row["config"], "queued", "Väntar på skannern", "", "", now, None))
        return run_id

    def claim_due(self, now=None):
        now = time.time() if now is None else now
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM schedules WHERE enabled=1 AND next_due<=?", (now,)).fetchall()
            for row in rows:
                config = json.loads(row["config"])
                missed = now-row["next_due"] > 300
                run_id = secrets.token_urlsafe(24)
                db.execute("INSERT OR IGNORE INTO schedule_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)", (run_id, row["channel_id"], row["revision"], row["next_due"], row["config"], "missed" if missed else "queued", "Väntar på skannern", "", "Tjänsten var inte tillgänglig i tid." if missed else "", now, now if missed else None))
                db.execute("UPDATE schedules SET next_due=? WHERE channel_id=? AND revision=?", (next_due(config, now), row["channel_id"], row["revision"]))
            db.execute("UPDATE schedule_runs SET state='missed',error='Skannern var upptagen för länge.',finished=? WHERE state='queued' AND due<?", (now, now-300))
            db.execute("DELETE FROM schedule_runs WHERE created<?", (now-30*86400,))

    def queued(self):
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM schedule_runs WHERE state='queued' ORDER BY due LIMIT 1").fetchone()
        if not row:
            return None
        result = dict(row)
        result["config"] = json.loads(result["config"])
        return result

    def start(self, run_id):
        with self.store.connect() as db:
            return db.execute("UPDATE schedule_runs SET state='running' WHERE id=? AND state='queued'", (run_id,)).rowcount == 1

    def update(self, run_id, *, state="running", progress="", result=None, error=""):
        with self.store.connect() as db:
            db.execute("UPDATE schedule_runs SET state=?,progress=?,result=?,error=?,finished=? WHERE id=?", (state, progress, json.dumps(result) if result is not None else "", error, None if state == "running" else time.time(), run_id))


class Scheduler:
    def __init__(self, services, schedules, runner):
        self.services, self.schedules, self.runner = services, schedules, runner
        with schedules.store.connect() as db:
            db.execute("UPDATE schedule_runs SET state='interrupted',error='Tjänsten startades om under körningen. Resultatet är inte bekräftat levererat.',finished=? WHERE state='running'", (time.time(),))

    def execute(self, run):
        channel, config = run["channel_id"], run["config"]
        audience = None
        def authorize():
            nonlocal audience
            current = self.schedules.get(channel)
            if not current or not current["enabled"] or current["revision"] != run["revision"]:
                raise ScheduleError(403, "Schemat har ändrats eller pausats. Inga nya resultat publiceras.")
            fresh = self.services.scheduled_audience(channel, config["namespaces"])
            if fresh.get("policy") != config["sharingPolicy"]:
                raise ScheduleError(403, "Kanalens delningspolicy har ändrats. Spara schemat igen.")
            if audience and fresh != audience:
                raise ScheduleError(403, "Kanalmedlemmar eller behörigheter ändrades under körningen.")
            audience = fresh
        try:
            authorize()
            result = self.services.scheduled_scanner().scan(config["namespaces"], authorize,
                lambda progress: self.schedules.update(run["id"], progress=progress), force=config["mode"] == "scan")
            result.update(scheduled=True, sharingPolicy=audience["policy"], scheduleTimezone=config["timezone"])
            authorize()
            result["reportFileIds"] = self.services.upload_report(channel, result)
            authorize()
            post = self.services.send_callback("", result, shared=True, channel_id=channel)
            summary = {"post_id": post["id"], "scannedImages": result["scannedImages"], "findings": len(result["rows"]), "namespaces": result["namespaces"]}
            partial = result["failedImages"] or result["unscannedImages"] or result.get("partialImages") or result.get("truncated")
            self.schedules.update(run["id"], state="partial" if partial else "done", result=summary)
        except Exception as exc:
            LOG.warning("scheduled_run_failed type=%s", type(exc).__name__)
            message = getattr(exc, "message", "Körningen misslyckades. Leveransen är inte bekräftad; kontrollera tjänsterna.")
            self.schedules.update(run["id"], state="failed", error=message)
            # A scanner outage must not look like a clean daily report. Notify
            # only the still-approved, unchanged audience; no finding data.
            try:
                authorize()
                self.services.send_callback("", {"kind":"schedule_error", "checkedAt":datetime.now(timezone.utc).isoformat()}, shared=True, channel_id=channel)
            except Exception:
                LOG.warning("schedule_failure_notification_not_delivered")
        finally:
            self.runner.lock.release()

    def tick(self, now=None):
        self.schedules.claim_due(now)
        run = self.schedules.queued()
        if not run or not self.runner.lock.acquire(blocking=False):
            return
        if not self.schedules.start(run["id"]):
            self.runner.lock.release()
            return
        threading.Thread(target=self.execute, args=(run,), daemon=True).start()

    def loop(self):
        while True:
            try:
                self.tick()
            except Exception:
                LOG.exception("scheduler_tick_failed")
            time.sleep(15)
