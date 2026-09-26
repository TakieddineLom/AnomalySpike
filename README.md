# AnomalyStrike

AI-assisted network security monitoring platform. Combines Suricata (signature-based IDS), Zeek (network telemetry), a hybrid ML/behavioral anomaly detection engine, and a RAG-based security knowledge search — all surfaced through a web dashboard.

## Architecture 
Suricata (IDS) ──┐
├─→ Collectors ─→ OpenSearch ─→ FastAPI ─→ Web Dashboard
Zeek (telemetry) ─┘ ↑
│
features.py (cron, every minute)
│
↓
detection/engine.py (cron, every minute)
│
↓
anomalystrike-anomalies index

**Data flow:**
1. Suricata and Zeek capture live traffic on `ens33` and write to their own log files.
2. Dedicated collectors tail those logs and write normalized documents into OpenSearch (`anomalystrike-alerts`, `anomalystrike-events`).
3. `features.py` aggregates raw events into 1-minute host-behavior windows (`anomalystrike-features`).
4. `detection/engine.py` scores each window with a hybrid behavioral + ML model, writing flagged anomalies to `anomalystrike-anomalies`.
5. The FastAPI backend (`backend/app/main.py`) serves both the REST API and the static web dashboard from the same origin.
6. A RAG pipeline (`backend/app/rag/`) provides semantic search over a small security-knowledge base (MITRE ATT&CK, network behavior notes), surfaced live in the anomaly investigation modal.

## Web pages

| Page | Route | Data source |
|---|---|---|
| Dashboard | `/dashboard` | stats, events chart, anomalies overview |
| Suricata Alerts | `/alerts` | `anomalystrike-alerts` |
| Connections | `/connections` | `anomalystrike-events` (Zeek conn.log) |
| DNS Analysis | `/dns` | `anomalystrike-events` (Zeek dns.log) — *currently reading a static test file, not live Zeek output* |
| Threat Detection | `/threats` | `anomalystrike-anomalies`, with RAG-backed knowledge in the investigation modal |
| Connected Hosts | `/hosts` | live aggregation over `anomalystrike-events` |
| Settings | `/settings` | monitored interface selection |

## Services (systemd)

All core components run as systemd services, enabled to start on boot:

- `anomalystrike-backend` — FastAPI + web dashboard (port 8000)
- `anomalystrike-zeek` — Zeek sensor on `ens33`
- `anomalystrike-zeek-collector` — ingests Zeek connection events
- `anomalystrike-zeek-dns-collector` — ingests Zeek DNS events (reads a static test file, see note above)
- `anomalystrike-suricata-collector` — ingests Suricata alerts

Suricata itself and OpenSearch (Docker, `unless-stopped` restart policy) run independently and also survive reboot.

### Common operations

```bash
# Check everything
sudo systemctl status anomalystrike-backend anomalystrike-zeek anomalystrike-zeek-collector anomalystrike-zeek-dns-collector anomalystrike-suricata-collector --no-pager

# Stop everything
sudo systemctl stop anomalystrike-backend anomalystrike-zeek anomalystrike-zeek-collector anomalystrike-zeek-dns-collector anomalystrike-suricata-collector

# Start everything
sudo systemctl start anomalystrike-backend anomalystrike-zeek anomalystrike-zeek-collector anomalystrike-zeek-dns-collector anomalystrike-suricata-collector

# Restart one service (e.g. after a code change)
sudo systemctl restart anomalystrike-backend

# Tail a service's logs
sudo journalctl -u anomalystrike-backend -f
```

`features.py` and `detection/engine.py` run via cron (every minute), not systemd — check with `crontab -l`, logs in `logs/features.log` and `logs/detection.log`.

**Never** start any of these components manually outside systemd/cron — doing so risks running duplicate processes alongside the managed ones (this happened once with Zeek; see git history / past incident).

## Changing the monitored interface

Saving a new interface in Settings updates `config/monitoring.json`, but Zeek and Suricata only read their interface at startup. After changing it:

```bash
sudo systemctl restart anomalystrike-zeek
# Suricata's interface is configured separately in /etc/suricata/suricata.yaml
```

## Known limitations / open items

- DNS collector reads from a static test file (`data/zeek/json-test/dns.log`), not Zeek's live `dns.log` — DNS Analysis page shows fixed sample data.
- Suricata collector re-anchors to end-of-file on every restart; alerts generated during a crash/restart window are not backfilled.
- RAG knowledge base is small (11 chunks, MITRE ATT&CK + network behavior notes) — retrieval quality will improve with more content.
- ML anomaly flag rate should be periodically checked against real idle traffic; retrain via `backend/app/models/train.py` if it over-flags.

## Development

```bash
cd ~/AnomalyStrike
source .venv/bin/activate

# Validate Python syntax before restarting a service
.venv/bin/python -m py_compile backend/app/main.py

# Validate JS syntax before reloading the frontend
node --check backend/app/static/renderer.js
```
