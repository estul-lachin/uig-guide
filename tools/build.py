#!/usr/bin/env python3
"""Render guide.uig.me: evidence that I use Splunk, Microsoft Sentinel and Wazuh on real data.

Sources (all in this repo):
  cases/<id>.md          my investigation reports on real honeypot incidents (front matter + Markdown);
                         a case is published only once its `date` is set
  playbooks/<id>.yml     one investigation question as SPL, KQL and Wazuh queries; a playbook is published
                         only when every query in it has a current result in results/verified.json
  recordings/<id>.yml    my screen recordings (media in recordings/media/); published once `date` is set
                         and the file exists
  certs.yml              certificates I hold, each with the issuer's verification link
  data/incidents.json    tools/incidents.py: what I did with the real Sentinel incidents (counts only)
  data/activity.json     tools/activity.py: searches I ran per day (counts only)
  results/verified.json  tools/verify.py: rows and a hash of the key column per query (no values)

Plain HTML and CSS, no JavaScript. Every value is escaped, except the Markdown I wrote.
--check fails on a stale verification (query changed since it was run), a malformed source, or anything
in the output that looks like a public IP address, an email address or a GUID.

  python tools/build.py [--site _site] [--check]
"""

import argparse
import datetime
import hashlib
import html
import json
import re
import shutil
import sys
from pathlib import Path

import markdown
import yaml

ROOT = Path(__file__).resolve().parent.parent
SITE = "https://guide.uig.me"
REPO = "https://github.com/estul-lachin/uig-guide"
OWNER = "Estul Lachin"
TOOLS = {"splunk": "Splunk", "sentinel": "Microsoft Sentinel", "wazuh": "Wazuh"}
QUERY_LANG = {"splunk": "SPL", "sentinel": "KQL", "wazuh": "DQL + OpenSearch query"}
CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; media-src 'self'; "
       "base-uri 'none'; form-action 'none'")
DESCRIPTION = ("Proof of hands-on SOC work: real honeypot incidents I triaged in Microsoft Sentinel, "
               "investigations, recordings, and the same queries verified in Splunk, Sentinel and Wazuh.")
e = html.escape


class SourceError(Exception):
    pass


# ---------------------------------------------------------------- loading

def front_matter(path):
    text = path.read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n?(.*)", text, re.S)
    if not m:
        raise SourceError(f"{path.name}: no front matter (--- ... ---)")
    meta = yaml.safe_load(m.group(1)) or {}
    return meta, m.group(2)


def as_date(v, where):
    if v in (None, ""):
        return None
    if isinstance(v, datetime.date):
        return v.isoformat()
    if isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return v
    raise SourceError(f"{where}: date must be YYYY-MM-DD, got {v!r}")


def slug_ok(name, where):
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name):
        raise SourceError(f"{where}: file name must be lowercase-hyphenated")


def load_cases():
    out = []
    for p in sorted((ROOT / "cases").glob("*.md")):
        if p.name.startswith("_"):
            continue
        slug_ok(p.stem, p.name)
        meta, body = front_matter(p)
        tool = meta.get("tool")
        if tool not in TOOLS:
            raise SourceError(f"{p.name}: tool must be one of {', '.join(TOOLS)}")
        out.append({"id": p.stem, "title": meta.get("title") or p.stem, "date": as_date(meta.get("date"), p.name),
                    "tool": tool, "summary": meta.get("summary") or "", "incident": meta.get("incident"),
                    "techniques": meta.get("techniques") or [], "recording": meta.get("recording"),
                    "playbooks": meta.get("playbooks") or [], "body": body})
    return out


def query_text(pb, tool):
    """The exact text a verification covers: changing it makes the stored result stale."""
    q = pb.get(tool)
    if tool == "wazuh" and isinstance(q, dict):
        return "DQL:\n" + (q.get("dql") or "").strip() + "\n\nDSL:\n" + (q.get("dsl") or "").strip()
    return (q or "").strip()


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def load_playbooks():
    out = []
    for p in sorted((ROOT / "playbooks").glob("*.yml")):
        if p.name.startswith("_"):
            continue
        slug_ok(p.stem, p.name)
        pb = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        for k in ("title", "question", "compare"):
            if not pb.get(k):
                raise SourceError(f"{p.name}: missing {k}")
        if not isinstance(pb["compare"], list):
            raise SourceError(f"{p.name}: compare must be a list of column names")
        tools = [t for t in TOOLS if pb.get(t)]
        if not tools:
            raise SourceError(f"{p.name}: no query")
        if "wazuh" in tools and not (isinstance(pb["wazuh"], dict) and pb["wazuh"].get("dsl")):
            raise SourceError(f"{p.name}: wazuh needs dql and dsl")
        pb.update(id=p.stem, tools=tools, sha={t: sha(query_text(pb, t)) for t in tools})
        out.append(pb)
    return out


def load_recordings():
    out = []
    for p in sorted((ROOT / "recordings").glob("*.yml")):
        if p.name.startswith("_"):
            continue
        slug_ok(p.stem, p.name)
        r = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if r.get("tool") not in TOOLS:
            raise SourceError(f"{p.name}: tool must be one of {', '.join(TOOLS)}")
        r.update(id=p.stem, date=as_date(r.get("date"), p.name))
        f = r.get("file")
        r["exists"] = bool(f) and (ROOT / "recordings" / "media" / f).is_file()
        if r.get("date") and not r["exists"]:
            raise SourceError(f"{p.name}: date is set but recordings/media/{f} is missing")
        out.append(r)
    return out


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def load_certs():
    p = ROOT / "certs.yml"
    certs = (yaml.safe_load(p.read_text(encoding="utf-8")) if p.is_file() else None) or []
    for c in certs:
        if not (c.get("name") and c.get("issuer") and str(c.get("verify", "")).startswith("https://")):
            raise SourceError("certs.yml: every certificate needs name, issuer and an https verify link")
        c["date"] = as_date(c.get("date"), "certs.yml")
    return certs


# ---------------------------------------------------------------- verification state

def verification(pb, results):
    """Per tool: the stored result if it covers the current query text, else None."""
    got = results.get(pb["id"], {})
    out, stale = {}, []
    for t in pb["tools"]:
        r = got.get(t)
        if r and r.get("sha") == pb["sha"][t]:
            out[t] = r
        else:
            out[t] = None
            if r:
                stale.append(t)
    return out, stale


def agreement(ver):
    """True if all verified tools saw the same rows on the same day, False if not, None if fewer than two."""
    done = [r for r in ver.values() if r]
    if len(done) < 2:
        return None
    return len({(r["day"], r["rows"], r["key_hash"]) for r in done}) == 1


# ---------------------------------------------------------------- page chrome

def page(title, body, depth, current="", description=DESCRIPTION):
    rel = "/" if depth is None else "../" * depth
    home = rel or "./"
    sub = [("Evidence", home, "home"), ("Cases", f"{rel}cases/", "cases"),
           ("Playbooks", f"{rel}playbooks/", "playbooks"), ("Recordings", f"{rel}recordings/", "recordings")]
    subnav = " · ".join(f'<a href="{h}"{" aria-current=\"page\"" if k == current else ""}>{n}</a>'
                        for n, h, k in sub if k in PUBLISHED)
    full = f"SOC field guide · {OWNER}" if not title else f"{title} · {OWNER}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="strict-origin-when-cross-origin">
<title>{e(full)}</title>
<meta name="description" content="{e(description)}">
<meta property="og:title" content="{e(full)}">
<meta property="og:description" content="{e(description)}">
<meta property="og:type" content="website">
<meta property="og:image" content="{SITE}/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Estul Lachin: SOC field guide">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="{rel}favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{rel}style.css">
</head>
<body>
<header class="site-header">
  <div class="wrap">
    <a class="brand" href="https://uig.me/">{OWNER}</a>
    <nav>
      <a href="https://lab.uig.me/">Labs</a>
      <a href="https://lab.uig.me/timeline/">Timeline</a>
      <a href="https://honeypot.uig.me/">Honeypot</a>
      <a href="https://detections.uig.me/">Detections</a>
      <a href="{home}" aria-current="page">Guide</a>
    </nav>
  </div>
</header>
<main class="wrap">
<p class="subnav">{subnav}</p>
{body}
</main>
<footer class="site-footer">
  <div class="wrap">
    <a href="https://www.linkedin.com/in/estul-lachin">LinkedIn</a> ·
    <a href="https://github.com/estul-lachin">GitHub</a> ·
    <a href="{REPO}">Source</a>
    <p class="credit">Attacker addresses are replaced by stable pseudonyms (src-xxxxxxxx) in every query result,
      recording and report.</p>
  </div>
</footer>
</body>
</html>
"""


PUBLISHED = {"home"}  # filled in build(): sections with at least one published item


def md(text, depth=2):
    out = markdown.Markdown(extensions=["extra", "sane_lists"], output_format="html").convert(text or "")
    # screenshots/<id>/x.png in a case or playbook points at the site's /screenshots/
    return re.sub(r'(src|href)="screenshots/', rf'\1="{"../" * depth}screenshots/', out)


def tool_tag(t):
    return f'<span class="tool">{e(TOOLS[t])}</span>'


def chips(techniques):
    return " ".join(f'<a class="chip" href="https://attack.mitre.org/techniques/{e(t.replace(".", "/"))}/" '
                    f'rel="noopener">{e(t)}</a>' for t in techniques)


def plural(n, word):
    return f"{n:,} {word}{'' if n == 1 else 'es' if word.endswith(('s', 'sh', 'ch', 'x')) else 's'}"


def duration(minutes):
    return f"{minutes:,} min" if minutes < 120 else f"{minutes / 60:.1f} h" if minutes < 48 * 60 else f"{minutes / 1440:.1f} days"


def fmt_minutes(secs):
    return f"{secs / 60:.0f} min" if secs >= 60 else f"{secs} s"


# ---------------------------------------------------------------- pages

def evidence_home(ctx):
    inc, act, cases, pbs, recs, certs = (ctx[k] for k in ("incidents", "activity", "cases", "playbooks",
                                                           "recordings", "certs"))
    cards = []
    if inc and inc.get("closed_by_me"):
        med = inc.get("close_minutes_median")
        cards.append((f'{inc["closed_by_me"]:,}', "real incidents I closed",
                      f'{inc["with_my_comment"]:,} with my written reasoning'
                      + (f" · median {duration(med)} from alert to my verdict" if med is not None else "")
                      + ' · <a href="#incidents">ledger</a>'))
    if cases:
        cards.append((str(len(cases)), "investigation reports", '<a href="cases/">read them</a>'))
    if recs:
        total = sum(r.get("seconds", 0) for r in recs)
        cards.append((str(len(recs)), "screen recordings",
                      (f"{fmt_minutes(total)} in total · " if total else "") + '<a href="recordings/">watch</a>'))
    if pbs:
        tools = sorted({t for p in pbs for t, r in p["ver"].items() if r}, key=list(TOOLS).index)
        cards.append((str(len(pbs)), "verified playbooks",
                      " / ".join(TOOLS[t] for t in tools) + ' · <a href="playbooks/">queries</a>'))
    if act and act.get("days"):
        recent = sum(n for d, n in act["days"].items() if d >= ctx["since30"])
        cards.append((f"{recent:,}", "searches I ran, last 30 days", '<a href="#activity">calendar</a>'))
    if certs:
        cards.append((str(len(certs)), "certificates", '<a href="#certificates">verify</a>'))

    body = ["<h1>SOC field guide</h1>",
            '<p class="lead">What I actually did with Splunk, Microsoft Sentinel and Wazuh, on live data from '
            '<a href="https://honeypot.uig.me/">my honeypot</a>. Each number below comes from the tool itself '
            "(Azure's incident log, Splunk's audit index), not from me typing it in.</p>"]
    if cards:
        body.append('<ul class="evidence">' + "".join(
            f'<li><span class="num">{e(n)}</span><span class="label">{e(lbl)}</span><span class="src">{src}</span></li>'
            for n, lbl, src in cards) + "</ul>")
    else:
        body.append('<p class="meta">Nothing published yet.</p>')
    if cases:
        body.append("<h2>Latest investigations</h2>" + case_list(cases[:4], ""))
    if inc and inc.get("closed_by_me"):
        body.append(incident_section(inc))
    if act and act.get("days"):
        body.append(activity_section(act))
    if certs:
        body.append('<h2 id="certificates">Certificates</h2><ul>' + "".join(
            f'<li>{e(c["name"])} · {e(c["issuer"])}{" · " + e(c["date"]) if c["date"] else ""} · '
            f'<a href="{e(c["verify"])}" rel="noopener">verify</a></li>' for c in certs) + "</ul>")
    return page("", "\n".join(body), 0, "home")


def incident_section(inc):
    cls = inc.get("classification") or {}
    rows = "".join(f"<tr><td>{e(k)}</td><td>{v:,}</td></tr>" for k, v in cls.items() if v)
    daily = inc.get("daily") or []
    drows = "".join(f'<tr><td>{e(d["day"])}</td><td>{d["closed_by_me"]:,}</td></tr>' for d in daily[-14:])
    return f"""<h2 id="incidents">Incident ledger</h2>
<div class="prose"><p>The honeypot's alerts become incidents in Microsoft Sentinel. A playbook enriches every
incident and closes the clear-cut Low ones; the rest wait for an analyst. These are the ones I triaged and closed
myself, counted from Sentinel's own <code>SecurityIncident</code> log (who changed the status, and when). Bulk
cleanups and test incidents are left out.</p></div>
<p class="meta">{plural(inc["incidents"], "incident")} since {e(inc["since"])} ·
{inc["closed_by_playbook"]:,} closed by my playbook · {inc["closed_by_me"]:,} closed by me ·
{inc["open"]:,} still open · updated {e(inc["generated_at"][:10])}</p>
<div class="prose"><table><thead><tr><th>My verdict</th><th>Incidents</th></tr></thead><tbody>{rows}</tbody></table>
{"<table><thead><tr><th>Day</th><th>Closed by me</th></tr></thead><tbody>" + drows + "</tbody></table>" if drows else ""}
</div>"""


def activity_section(act):
    days = act["days"]
    end = datetime.date.fromisoformat(act["generated_at"][:10])
    start = end - datetime.timedelta(days=7 * 26 - 1)
    start -= datetime.timedelta(days=(start.weekday() + 1) % 7)  # weeks start on Sunday
    cells, d = [], start
    while d <= end:
        n = days.get(d.isoformat(), 0)
        lvl = 0 if n == 0 else 1 if n < 5 else 2 if n < 20 else 3 if n < 50 else 4
        cells.append(f'<span class="l{lvl}" title="{d.isoformat()}: {n}"></span>')
        d += datetime.timedelta(days=1)
    total = sum(days.values())
    return f"""<h2 id="activity">Hands-on activity</h2>
<p class="meta">{plural(total, "search")} I ran in {e(act.get("source", ""))}, per day, last 26 weeks ·
updated {e(act["generated_at"][:10])}</p>
<div class="calendar" role="img" aria-label="Searches per day over the last 26 weeks">{"".join(cells)}</div>"""


def case_list(cases, rel):
    return '<ul class="items">' + "".join(
        f'<li class="item"><div class="item-head"><a href="{rel}cases/{c["id"]}/">{e(c["title"])}</a>'
        f'{tool_tag(c["tool"])}</div><p>{e(c["summary"])}</p>'
        f'<p class="meta">{e(c["date"])} {chips(c["techniques"])}</p></li>' for c in cases) + "</ul>"


def case_page(c, ctx):
    rec = ctx["rec_by_id"].get(c["recording"])
    pbs = [ctx["pb_by_id"][p] for p in c["playbooks"] if p in ctx["pb_by_id"]]
    extra = ""
    if rec:
        extra += f'<h2>Recording</h2>{video(rec, 2)}'
    if pbs:
        extra += "<h2>Queries used</h2><ul>" + "".join(
            f'<li><a href="../../playbooks/{p["id"]}/">{e(p["title"])}</a></li>' for p in pbs) + "</ul>"
    inc = f' · Sentinel incident #{e(str(c["incident"]))}' if c["incident"] else ""
    body = f"""<h1>{e(c["title"])}</h1>
<p class="meta">{e(c["date"])} · led in {tool_tag(c["tool"])}{inc} {chips(c["techniques"])}</p>
<div class="prose">{md(c["body"])}</div>
{extra}"""
    return page(c["title"], body, 2, "cases", c["summary"] or DESCRIPTION)


def playbook_list(pbs):
    return '<ul class="items">' + "".join(
        f'<li class="item"><div class="item-head"><a href="{p["id"]}/">{e(p["title"])}</a></div>'
        f'<p>{e(p["question"])}</p><p class="meta">'
        + " ".join(tool_tag(t) for t in p["tools"]) + f' {chips(p.get("techniques") or [])}</p></li>'
        for p in pbs) + "</ul>"


def playbook_page(p):
    agree = agreement(p["ver"])
    groups = {}
    for t in p["tools"]:
        r = p["ver"][t]
        groups.setdefault((r["day"], r["rows"], r["key_hash"]), []).append(TOOLS[t])
    biggest = max(map(len, groups.values()))
    blocks = []
    for t in p["tools"]:
        r = p["ver"][t]
        mates = len(groups[(r["day"], r["rows"], r["key_hash"])])
        cls = "badge" + ("" if agree is None else " agree" if mates == biggest and mates > 1 else " differ")
        badge = (f'<span class="{cls}">verified {e(r["day"])} data · {plural(r["rows"], "row")} · '
                 f'{e(r.get("version", ""))}</span>')
        if t == "wazuh":
            q = (f'<p class="label-sm">Discover filter (DQL)</p><pre class="code"><code>{e(p[t]["dql"].strip())}</code></pre>'
                 f'<p class="label-sm">Aggregation (OpenSearch query DSL, Dev Tools or API)</p>'
                 f'<pre class="code"><code>{e(p[t]["dsl"].strip())}</code></pre>')
        else:
            q = f'<pre class="code"><code>{e(p[t].strip())}</code></pre>'
        blocks.append(f'<section class="siem"><div class="siem-head"><h3>{e(TOOLS[t])} '
                      f'<span class="muted">{e(QUERY_LANG[t])}</span></h3>{badge}</div>{q}</section>')
    if agree:
        verdict = (f'<p class="meta">{"Both" if len(p["tools"]) == 2 else f"All {len(p['tools'])}"} tools returned '
                   f'the same rows (same count, same {", ".join(f"<code>{e(c)}</code>" for c in p["compare"])} values).</p>')
    elif agree is False:
        parts = [" and ".join(names) + f" returned {plural(k[1], 'row')}" for k, names in
                 sorted(groups.items(), key=lambda kv: -len(kv[1]))]
        verdict = f'<p class="meta">{e("; ".join(parts))}. Why they differ is explained below.</p>'
    else:
        verdict = ""
    notes = f'<h2>My notes</h2><div class="prose">{md(p["my_notes"])}</div>' if p.get("my_notes") else ""
    body = f"""<p class="subnav"><a href="../">All playbooks</a></p>
<h1>{e(p["title"])}</h1>
<p class="lead">{e(p["question"])}</p>
<p class="meta">{chips(p.get("techniques") or [])}</p>
<div class="prose">{md(p.get("concepts"))}</div>
<h2>Queries</h2>{verdict}
{"".join(blocks)}
{f'<div class="prose">{md(p["differences"])}</div>' if p.get("differences") else ""}
{notes}"""
    return page(p["title"], body, 2, "playbooks", p["question"])


def video(r, depth):
    rel = "../" * depth
    poster = f' poster="{rel}recordings/media/{e(r["poster"])}"' if r.get("poster") else ""
    track = (f'<track kind="captions" src="{rel}recordings/media/{e(r["captions"])}" srclang="en" label="English" default>'
             if r.get("captions") else "")
    ch = ""
    if r.get("chapters"):
        ch = '<ol class="chapters">' + "".join(
            f'<li><span class="t">{e(str(c["t"]))}</span>{e(c["label"])}</li>' for c in r["chapters"]) + "</ol>"
    return (f'<video controls preload="metadata"{poster}><source src="{rel}recordings/media/{e(r["file"])}">'
            f'{track}</video>{ch}')


def recordings_page(recs):
    items = "".join(f'<section><h2 id="{r["id"]}">{e(r["title"])}</h2><p class="meta">{tool_tag(r["tool"])} · '
                    f'recorded {e(r["date"])}</p><p class="muted">{e(r.get("summary", ""))}</p>{video(r, 1)}</section>'
                    for r in recs)
    body = ('<h1>Recordings</h1><p class="lead">Unedited screen recordings of me working in each tool on the '
            'honeypot data. Addresses are pseudonymized at the source, not blurred afterwards.</p>' + items)
    return page("Recordings", body, 1, "recordings")


def notfound():
    body = '<h1>Not found</h1><p>That page doesn\'t exist. <a href="/">Back to the evidence</a></p>'
    return page("Not found", body, None).replace('<main class="wrap">', '<main class="wrap notfound">')


# ---------------------------------------------------------------- leak scan

ALLOWED_NETS = (r"^(10|127)\.", r"^192\.168\.", r"^172\.(1[6-9]|2\d|3[01])\.", r"^192\.0\.2\.", r"^198\.51\.100\.",
                r"^203\.0\.113\.", r"^0\.0\.0\.0$", r"^255\.")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z.]{2,}")
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def leak_scan(site):
    problems = []
    for f in site.rglob("*"):
        if f.suffix not in (".html", ".json", ".xml", ".txt", ".vtt"):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for ip in IPV4.findall(text):
            if all(int(o) <= 255 for o in ip.split(".")) and not any(re.match(n, ip) for n in ALLOWED_NETS):
                problems.append(f"{f.relative_to(site)}: public IP {ip}")
        problems += [f"{f.relative_to(site)}: email {m}" for m in EMAIL.findall(text)]
        problems += [f"{f.relative_to(site)}: GUID {m}" for m in GUID.findall(text)]
    return problems


# ---------------------------------------------------------------- build

def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build(out, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    results = load_json(ROOT / "results" / "verified.json") or {}
    problems = []

    cases = sorted((c for c in load_cases() if c["date"]), key=lambda c: c["date"], reverse=True)
    playbooks = []
    for p in load_playbooks():
        p["ver"], stale = verification(p, results)
        problems += [f"playbooks/{p['id']}.yml: {t} query changed since it was verified; run tools/verify.py"
                     for t in stale]
        if all(p["ver"].values()):
            playbooks.append(p)
    for c in cases:
        for pid in c["playbooks"]:
            if pid not in {p["id"] for p in playbooks}:
                problems.append(f"cases/{c['id']}.md: playbook {pid} is not published (missing or unverified)")
    recordings = sorted((r for r in load_recordings() if r["date"]), key=lambda r: r["date"], reverse=True)
    for c in cases:
        if c["recording"] and c["recording"] not in {r["id"] for r in recordings}:
            problems.append(f"cases/{c['id']}.md: recording {c['recording']} is not published")

    ctx = {"incidents": load_json(ROOT / "data" / "incidents.json"),
           "activity": load_json(ROOT / "data" / "activity.json"),
           "cases": cases, "playbooks": playbooks, "recordings": recordings, "certs": load_certs(),
           "pb_by_id": {p["id"]: p for p in playbooks}, "rec_by_id": {r["id"]: r for r in recordings},
           "since30": (now - datetime.timedelta(days=30)).date().isoformat()}
    PUBLISHED.clear()
    PUBLISHED.update({"home"} | {k for k in ("cases", "playbooks", "recordings") if ctx[k]})

    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "site", out)
    for d in ("screenshots",):
        if (ROOT / d).is_dir():
            shutil.copytree(ROOT / d, out / d)
    if recordings:
        (out / "recordings" / "media").mkdir(parents=True)
        for r in recordings:
            for k in ("file", "poster", "captions"):
                if r.get(k):
                    shutil.copy2(ROOT / "recordings" / "media" / r[k], out / "recordings" / "media" / r[k])

    write(out / "index.html", evidence_home(ctx))
    write(out / "404.html", notfound())
    urls = [f"{SITE}/"]
    if cases:
        write(out / "cases" / "index.html", page("Investigations", "<h1>Investigations</h1><p class=\"lead\">"
              "Real incidents from my honeypot, worked from alert to verdict.</p>" + case_list(cases, "../"),
              1, "cases"))
        urls.append(f"{SITE}/cases/")
        for c in cases:
            write(out / "cases" / c["id"] / "index.html", case_page(c, ctx))
            urls.append(f"{SITE}/cases/{c['id']}/")
    if playbooks:
        write(out / "playbooks" / "index.html", page("Playbooks", "<h1>Playbooks</h1><p class=\"lead\">One "
              "investigation question, answered in Splunk, Microsoft Sentinel and Wazuh on the same day of honeypot "
              "data. Every query here was run and its result checked against the others.</p>"
              + playbook_list(playbooks), 1, "playbooks"))
        urls.append(f"{SITE}/playbooks/")
        for p in playbooks:
            write(out / "playbooks" / p["id"] / "index.html", playbook_page(p))
            urls.append(f"{SITE}/playbooks/{p['id']}/")
    if recordings:
        write(out / "recordings" / "index.html", recordings_page(recordings))
        urls.append(f"{SITE}/recordings/")

    inc = ctx["incidents"] or {}
    summary = {"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "cases": len(cases),
               "playbooks": len(playbooks), "recordings": len(recordings), "certificates": len(ctx["certs"]),
               "incidents_closed_by_me": inc.get("closed_by_me", 0)}
    write(out / "summary.json", json.dumps(summary, indent=1) + "\n")
    write(out / "sitemap.xml", '<?xml version="1.0" encoding="UTF-8"?>\n'
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
          + "".join(f"  <url><loc>{u}</loc></url>\n" for u in urls) + "</urlset>\n")
    write(out / "robots.txt", f"User-agent: *\nAllow: /\n\nSitemap: {SITE}/sitemap.xml\n")
    problems += leak_scan(out)
    return summary, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", default="_site", help="output directory (default _site)")
    ap.add_argument("--check", action="store_true", help="fail on stale verifications or leaks")
    a = ap.parse_args(argv)
    try:
        summary, problems = build(ROOT / a.site)
    except (SourceError, yaml.YAMLError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    for p in problems:
        print(("error: " if a.check else "warning: ") + p, file=sys.stderr)
    print(f"built {a.site}/: {summary['cases']} cases, {summary['playbooks']} playbooks, "
          f"{summary['recordings']} recordings, {summary['certificates']} certificates, "
          f"{summary['incidents_closed_by_me']} incidents closed by me")
    return 1 if (a.check and problems) else 0


if __name__ == "__main__":
    sys.exit(main())
