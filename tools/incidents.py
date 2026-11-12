#!/usr/bin/env python3
"""Count what I did with the real Sentinel incidents, for the evidence page (data/incidents.json).

Reads SecurityIncident in the honeypot workspace. For every incident it takes the latest state, and the
row where the status first became Closed: that row's ModifiedBy says who closed it. A close counts as
mine when ModifiedBy is a person, not "Playbook - ...", "Automation rule - ..." or "Alert Grouping".
Incidents tagged soar:legacy (bulk-closed when the SOAR automation went live) or soar:e2e-test
(tools/soar_e2e.py in uig-detections) are left out.

Writes only counts, verdicts and times: no IPs, titles, comment text or names.

Honesty rule: only the owner closes incidents. No script or AI session may change an incident's status,
or this ledger stops being evidence.

  python tools/incidents.py [--out data/incidents.json] [--resource-group rg-uig-sentinel] [--workspace law-uig-honeypot]

Uses the Azure CLI's login (az login); needs read access to the workspace only.
"""

import argparse
import datetime
import json
import statistics
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The SOAR "enrich every new incident" automation went live here (uig-detections tools/soar_stats.py).
SINCE = "2026-11-09T15:47:00Z"
DAYS = 90  # workspace retention

QUERY = f"""
let since = datetime({SINCE});
let closes = SecurityIncident
    | where Status == "Closed"
    | summarize arg_min(TimeGenerated, ModifiedBy, ClosedTime) by IncidentNumber
    | project IncidentNumber, Closer = ModifiedBy, FirstClosed = ClosedTime;
SecurityIncident
| where CreatedTime >= since
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend L = tostring(Labels), C = tostring(Comments)
| where not(L contains '"soar:legacy"' or L contains '"soar:e2e-test"')
| join kind=leftouter closes on IncidentNumber
| extend CloserKind = case(Status != "Closed", "",
    Closer startswith "Playbook - " or Closer startswith "Automation rule - " or Closer == "Alert Grouping",
    "machine", "person")
// every comment has one "name" key under author; playbook comments say "Comment created from playbook"
| extend MyComments = countof(C, '"name":"') - countof(C, "Comment created from playbook")
| project Day = format_datetime(FirstClosed, "yyyy-MM-dd"), Status, Classification, ClassificationReason,
    CloserKind, MyComments, Minutes = datetime_diff("minute", FirstClosed, CreatedTime)
"""

VERDICTS = {  # Sentinel classification + reason -> plain words
    ("TruePositive", "SuspiciousActivity"): "True positive: suspicious activity",
    ("BenignPositive", "SuspiciousButExpected"): "Benign positive: suspicious but expected",
    ("FalsePositive", "IncorrectAlertLogic"): "False positive: incorrect alert logic",
    ("FalsePositive", "InaccurateData"): "False positive: inaccurate data",
    ("Undetermined", ""): "Undetermined",
}


def az(*args):
    r = subprocess.run(["az", *args, "-o", "tsv"], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def query(rg, ws, kql, days=DAYS, timespan=None):
    sub = az("account", "show", "--query", "id")
    tok = az("account", "get-access-token", "--resource", "https://management.azure.com", "--query", "accessToken")
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/"
           f"Microsoft.OperationalInsights/workspaces/{ws}/api/query?api-version=2020-08-01")
    req = urllib.request.Request(url, data=json.dumps({"query": kql, "timespan": timespan or f"P{days}D"}).encode(),
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"query failed: {e.code} {e.read()[:400]!r}") from e
    # ARM's query endpoint capitalizes the keys (Tables, Columns, ColumnName); Log Analytics' does not
    table = (res.get("Tables") or res.get("tables"))[0]
    cols = [c.get("ColumnName") or c.get("name") for c in (table.get("Columns") or table.get("columns"))]
    return [dict(zip(cols, row)) for row in (table.get("Rows") or table.get("rows") or [])]


def verdict(r):
    key = (r["Classification"] or "Undetermined", r["ClassificationReason"] or "")
    return VERDICTS.get(key) or " ".join(x for x in key if x)


def stats(rows, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    mine = [r for r in rows if r["CloserKind"] == "person"]
    minutes = sorted(r["Minutes"] for r in mine if r["Minutes"] is not None and r["Minutes"] >= 0)
    daily = Counter(r["Day"] for r in mine)
    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since": SINCE[:10],
        "incidents": len(rows),
        "open": sum(1 for r in rows if r["Status"] != "Closed"),
        "closed_by_playbook": sum(1 for r in rows if r["CloserKind"] == "machine"),
        "closed_by_me": len(mine),
        "with_my_comment": sum(1 for r in mine if (r["MyComments"] or 0) > 0),
        "close_minutes_median": round(statistics.median(minutes)) if minutes else None,
        "classification": dict(Counter(verdict(r) for r in mine).most_common()),
        "daily": [{"day": d, "closed_by_me": daily[d]} for d in sorted(daily)],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / "data" / "incidents.json"))
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    a = ap.parse_args(argv)
    try:
        s = stats(query(a.resource_group, a.workspace, QUERY))
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1)
        f.write("\n")
    print(f"{s['incidents']} incidents since {s['since']}: {s['closed_by_me']} closed by me "
          f"({s['with_my_comment']} with a comment), {s['closed_by_playbook']} by automation, {s['open']} open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
