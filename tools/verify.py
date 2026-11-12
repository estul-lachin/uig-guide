#!/usr/bin/env python3
"""Run every playbook query on one UTC day of honeypot data and record what came back.

For each playbook and tool, the query runs over [day 00:00, day+1 00:00) UTC:
  splunk    the local honeypot Splunk (uig-honeypot ./hp siem up), index honeypot_demo, through the
            REST export endpoint inside the container (the management port is not published)
  sentinel  the workspace functions HP_Cowrie / HP_Suricata, through the Log Analytics query API
            (the API's timespan bounds TimeGenerated)
  wazuh     the local demo Wazuh indexer (uig-honeypot ./hp wazuh up)

Stored per query in results/verified.json: the sha of the query text, the day, the row count, and a
sha256 of the sorted values of the playbook's `compare` columns. Never the values themselves.

  SPLUNK_PASSWORD=... python tools/verify.py [--day YYYY-MM-DD] [--tools splunk,sentinel,wazuh] [--only ID,...] [--dry-run]

--dry-run prints the per-tool rows and agreement without writing results/verified.json.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build  # noqa: E402
import incidents  # noqa: E402  (Azure query helper)

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results" / "verified.json"


def norm(v):
    """Compare values the same way whatever the tool returned: "12", 12 and 12.0 are all "12"."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return str(v).lower()
    s = str(v)
    if re.fullmatch(r"-?\d+(\.0+)?", s):
        return str(int(float(s)))
    return s


def key_hash(rows, cols):
    missing = [c for c in cols if rows and c not in rows[0]]
    if missing:
        raise RuntimeError(f"result has no column {', '.join(missing)} (has {', '.join(rows[0])})")
    keys = sorted(json.dumps([norm(r.get(c)) for c in cols]) for r in rows)
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()


# ---------------------------------------------------------------- tools

class Splunk:
    def __init__(self, container, password):
        self.container, self.password = container, password
        img = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", container],
                             capture_output=True, text=True)
        if img.returncode:
            raise RuntimeError(f"container {container} is not running (./hp siem up in uig-honeypot)")
        self.version = "Splunk " + img.stdout.strip().rsplit(":", 1)[-1]

    def run(self, spl, start, end):
        q = spl.strip()
        body = urllib.parse.urlencode({"search": q if q.startswith("|") else "search " + q,
                                       "earliest_time": int(start.timestamp()), "latest_time": int(end.timestamp()),
                                       "output_mode": "json"})
        # the password goes in on stdin (curl -K -), never on a command line
        conf = f'user = "admin:{self.password}"\ndata = "{body}"\n'
        r = subprocess.run(["docker", "exec", "-i", self.container, "curl", "-sSk", "-K", "-",
                            "https://localhost:8089/services/search/v2/jobs/export"],
                           input=conf, capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"splunk export failed: {r.stderr.strip()}")
        rows = []
        for line in r.stdout.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("messages"):
                errs = [m["text"] for m in obj["messages"] if m.get("type") in ("ERROR", "FATAL")]
                if errs:
                    raise RuntimeError("splunk: " + "; ".join(errs))
            if "result" in obj and not obj.get("preview"):
                rows.append(obj["result"])
        return rows


class Wazuh:
    """OpenSearch query DSL against wazuh-alerts-4.x-* in the demo indexer (curl inside the container).

    The playbook's DSL holds `query` and `aggs`; the day is added as a filter on `timestamp`, which
    siem-wazuh/pipeline.sh sets to the event's own time. Aggregations become rows:
      bucket aggs (terms, filters) add a column named after the agg, one row per non-empty bucket;
      single-bucket aggs (filter) add the agg name = doc_count, their metrics as <agg>_<metric>;
      metric aggs (value_count, cardinality, min, ...) add a column; top_hits adds its first value.
    """

    def __init__(self, container, auth):
        self.container, self.auth = container, auth
        img = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", container],
                             capture_output=True, text=True)
        if img.returncode:
            raise RuntimeError(f"container {container} is not running (./hp wazuh up in uig-honeypot)")
        self.version = "Wazuh " + img.stdout.strip().rsplit(":", 1)[-1]

    def run(self, dsl, start, end):
        body = json.loads(dsl)
        day = {"range": {"timestamp": {"gte": f"{start:%Y-%m-%dT%H:%M:%SZ}", "lt": f"{end:%Y-%m-%dT%H:%M:%SZ}"}}}
        body["query"] = {"bool": {"filter": [day, body.get("query", {"match_all": {}})]}}
        body["size"] = 0
        # the demo password is documented and localhost-only, so -u on the command line is fine here
        r = subprocess.run(["docker", "exec", "-i", self.container, "curl", "-sSk", "-u", self.auth,
                            "-H", "Content-Type: application/json", "--data-binary", "@-",
                            "https://localhost:9200/wazuh-alerts-4.x-*/_search"],
                           input=json.dumps(body), capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"wazuh search failed: {r.stderr.strip()}")
        res = json.loads(r.stdout)
        if "error" in res:
            raise RuntimeError("wazuh: " + json.dumps(res["error"].get("root_cause", res["error"]))[:400])
        return list(self.rows(res.get("aggregations", {}), {}))

    @staticmethod
    def first_value(src):
        while isinstance(src, dict) and src:
            src = next(iter(src.values()))
        return src

    def rows(self, aggs, prefix):
        row, bucket_aggs = dict(prefix), []
        for name, a in aggs.items():
            if not isinstance(a, dict):
                continue
            if "buckets" in a:
                bucket_aggs.append((name, a["buckets"]))
            elif "hits" in a:
                hits = a["hits"]["hits"]
                row[name] = self.first_value(hits[0]["_source"]) if hits else None
            elif "doc_count" in a:
                row[name] = a["doc_count"]
                for sub, m in a.items():
                    if isinstance(m, dict) and "value" in m:
                        row[f"{name}_{sub}"] = m.get("value_as_string", m["value"])
            elif "value" in a:
                row[name] = a.get("value_as_string", a["value"])
        if len(bucket_aggs) > 1:
            raise RuntimeError("one bucket aggregation per level, got " + ", ".join(n for n, _ in bucket_aggs))
        if not bucket_aggs:
            yield row
            return
        name, buckets = bucket_aggs[0]
        items = buckets.items() if isinstance(buckets, dict) else ((b.get("key_as_string", b["key"]), b) for b in buckets)
        for key, b in items:
            if b.get("doc_count", 0) == 0:
                continue
            yield from self.rows({k: v for k, v in b.items() if k not in ("key", "key_as_string", "doc_count")},
                                 {**row, name: key})


class Sentinel:
    version = "Microsoft Sentinel (Log Analytics)"

    def __init__(self, rg, ws):
        self.rg, self.ws = rg, ws

    def run(self, kql, start, end):
        return incidents.query(self.rg, self.ws, kql, timespan=f"{start:%Y-%m-%dT%H:%M:%SZ}/{end:%Y-%m-%dT%H:%M:%SZ}")


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    yesterday = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).date().isoformat()
    ap.add_argument("--day", default=yesterday, help="UTC day to run on (default: yesterday)")
    ap.add_argument("--tools", default="splunk,sentinel,wazuh")
    ap.add_argument("--only", default="", help="comma-separated playbook ids")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--container", default="uig-honeypot-siem-splunk-1")
    ap.add_argument("--wazuh-container", default="uig-honeypot-wazuh-wazuh.indexer-1")
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    a = ap.parse_args(argv)

    start = datetime.datetime.fromisoformat(a.day).replace(tzinfo=datetime.timezone.utc)
    end = start + datetime.timedelta(days=1)
    wanted = [t.strip() for t in a.tools.split(",") if t.strip()]
    runners = {}
    try:
        if "splunk" in wanted:
            pw = os.environ.get("SPLUNK_PASSWORD")
            if not pw:
                print("set SPLUNK_PASSWORD (uig-honeypot's HP_SPLUNK_PASSWORD)", file=sys.stderr)
                return 2
            runners["splunk"] = Splunk(a.container, pw)
        if "sentinel" in wanted:
            runners["sentinel"] = Sentinel(a.resource_group, a.workspace)
        if "wazuh" in wanted:
            runners["wazuh"] = Wazuh(a.wazuh_container, os.environ.get("WAZUH_AUTH", "admin:Lab-Wazuh-2026"))
    except RuntimeError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    only = {x for x in a.only.split(",") if x}
    results = json.loads(RESULTS.read_text()) if RESULTS.is_file() else {}
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    failed = False
    for pb in build.load_playbooks():
        if only and pb["id"] not in only:
            continue
        got = {}
        for t in pb["tools"]:
            if t not in runners:
                continue
            q = pb[t] if t != "wazuh" else pb[t]["dsl"]
            try:
                rows = runners[t].run(q, start, end)
                got[t] = {"sha": pb["sha"][t], "day": a.day, "rows": len(rows), "key_hash": key_hash(rows, pb["compare"]),
                          "version": runners[t].version, "verified_at": now}
            except RuntimeError as err:
                print(f"  {pb['id']} {t}: error: {err}", file=sys.stderr)
                failed = True
        hashes = {(g["rows"], g["key_hash"]) for g in got.values()}
        status = "agree" if len(hashes) == 1 and len(got) > 1 else "DIFFER" if len(hashes) > 1 else "-"
        print(f"{pb['id']}: " + ", ".join(f"{t} {g['rows']} rows {g['key_hash'][:8]}" for t, g in got.items())
              + f"  [{status}]")
        if not got or not all(g["rows"] for g in got.values()):
            print(f"  {pb['id']}: no rows on {a.day}: pick another day, or the query is wrong", file=sys.stderr)
            failed = True
            continue
        results.setdefault(pb["id"], {}).update(got)
    if not a.dry_run:
        RESULTS.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
        print(f"wrote {RESULTS.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
