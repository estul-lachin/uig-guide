# uig-guide

Source of [guide.uig.me](https://guide.uig.me): evidence that I use Splunk, Microsoft Sentinel and Wazuh on
real data, from [my honeypot](https://honeypot.uig.me), and a field guide I keep for myself.

| Section | Source | Who writes it |
|---|---|---|
| Evidence summary | `data/incidents.json`, `data/activity.json`, everything below | generated |
| Incident ledger | `tools/incidents.py`: Sentinel's own `SecurityIncident` log, counts only | generated from my work |
| Cases | `cases/<id>.md` (template: `cases/_template.md`) | me |
| Recordings | `recordings/<id>.yml` + `recordings/media/` | me |
| Playbooks | `playbooks/<id>.yml`, results in `results/verified.json` | queries verified by `tools/verify.py` |
| Certificates | `certs.yml`, each with the issuer's verification link | me |

Nothing is published until it exists: a case or recording needs its `date`, a playbook needs a current
verification for every query, and empty sections are hidden.

## Privacy

The raw honeypot logs never leave my Mac. Recordings, reports and query results use a pseudonymized copy:
a public address becomes `src-` plus 8 hex characters of a salted SHA-256, and any address in free text
becomes `[ip]`. The same rule runs in all three tools (uig-honeypot `siem/pseudo.py` for Splunk and Wazuh,
`azure/demo-functions.sh` for the Sentinel functions `HP_Cowrie` and `HP_Suricata`), so their results can
be compared. `tools/build.py --check` fails if the built site contains a public IP, an email or a GUID.

## Build

```
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tools/build.py --check          # writes _site/
.venv/bin/python tools/incidents.py              # needs az login; writes data/incidents.json
```

The link-preview image `site/og-image.png` is rendered from `assets/og-image.html` with headless Chrome,
like the other uig.me sites:

```
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --hide-scrollbars \
  --window-size=1200,630 --screenshot="$PWD/site/og-image.png" "file://$PWD/assets/og-image.html"
```
