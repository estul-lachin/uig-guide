#!/usr/bin/env python3
"""Count the searches I ran by hand, per day, for the evidence page (data/activity.json).

  Splunk     the local honeypot Splunk's _audit index: completed searches whose provenance is UI:*
             (Search app, dashboards). Searches from scripts (CLI, rest:jobs: tools/verify.py,
             uig-detections' splunk_check.py) and scheduled ones are left out.
  Sentinel   LAQueryLogs in the honeypot workspace, only queries sent from the Azure portal
             (RequestClientApp names a portal client). Needs the workspace's audit diagnostic setting
             (uig-honeypot azure/query-audit.sh); without it the table is empty and this source is skipped.

Writes only counts per day: no search text, user names or IDs. Days already in data/activity.json are
kept, so the calendar keeps its history after Splunk's _audit is reset or ages out.

  SPLUNK_PASSWORD=... python tools/activity.py [--days 180] [--no-splunk] [--no-sentinel]
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import incidents  # noqa: E402  (Azure query helper)
import verify  # noqa: E402  (Splunk runner)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "activity.json"

SPL = ('index=_audit action=search info=completed provenance="UI:*" '
       '| eval day=strftime(_time, "%Y-%m-%d") | stats count by day')
# Portal clients; scripts using the API with an az token show up with other or empty names.
KQL = """LAQueryLogs
| where RequestClientApp in~ ("ASI_Portal", "AppAnalytics", "LogAnalyticsExtension", "AzureMonitorLogsBlade")
    or RequestClientApp has "Portal"
| summarize count = count() by day = format_datetime(TimeGenerated, "yyyy-MM-dd")"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=int, default=180)
    ap.add_argument("--no-splunk", action="store_true")
    ap.add_argument("--no-sentinel", action="store_true")
    ap.add_argument("--container", default="uig-honeypot-siem-splunk-1")
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    a = ap.parse_args(argv)

    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(days=a.days)).replace(hour=0, minute=0, second=0, microsecond=0)
    old = json.loads(OUT.read_text()) if OUT.is_file() else {}
    by_source = {k: dict(v) for k, v in (old.get("by_source") or {}).items()}

    if not a.no_splunk:
        pw = os.environ.get("SPLUNK_PASSWORD")
        if not pw:
            print("set SPLUNK_PASSWORD (uig-honeypot's HP_SPLUNK_PASSWORD), or pass --no-splunk", file=sys.stderr)
            return 2
        try:
            rows = verify.Splunk(a.container, pw).run(SPL, start, now)
            by_source.setdefault("Splunk", {}).update({r["day"]: int(r["count"]) for r in rows})
        except RuntimeError as err:
            print(f"error: splunk: {err}", file=sys.stderr)
            return 1
    if not a.no_sentinel:
        try:
            rows = incidents.query(a.resource_group, a.workspace, KQL, days=a.days)
            if rows:
                by_source.setdefault("Microsoft Sentinel", {}).update({r["day"]: int(r["count"]) for r in rows})
            else:
                print("sentinel: no portal queries in LAQueryLogs (is azure/query-audit.sh applied?)")
        except RuntimeError as err:
            print(f"error: sentinel: {err}", file=sys.stderr)
            return 1

    days = {}
    for src in by_source.values():
        for d, n in src.items():
            days[d] = days.get(d, 0) + n
    out = {"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "source": " and ".join(sorted(k for k, v in by_source.items() if v)),
           "days": dict(sorted(days.items())), "by_source": {k: dict(sorted(v.items())) for k, v in by_source.items()}}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(f"{sum(days.values())} hands-on searches on {len(days)} day(s): "
          + ", ".join(f"{k} {sum(v.values())}" for k, v in by_source.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
