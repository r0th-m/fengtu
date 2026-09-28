<div align="center">

# FengTu (丰图)

**A server-side analysis platform for incident response — intent-chain driven, human-verdicted, chain of custody never breaks.**

Upload collection packages → parse & index → intent-chain AI investigation → human verdicts → report

[Quick start](#quick-start-docker-compose-recommended) · [Feature map](#feature-map-screenshots) · [Hardware](#recommended-hardware) · [Disclaimer](#security-statement--disclaimer-read-me-first)

</div>

FengTu is a **local-first, human-in-command** IR analysis platform: field
collection packages (WinInfoSC / LinuxSC) are uploaded, the pipeline normalizes
line-based logs and Windows forensic artifacts (evtx / registry hives / $MFT /
Prefetch / lnk / USN / EFU / JumpList / browser storages / SRUM …) into one
store, the rule engine and applicability-domain operators produce candidates,
and the intent-chain AI works through playbook templates — **everything the
machine produces is a candidate; the final verdict belongs to the human.**

## Highlights

- **Intent-chain investigation** — 14 playbook templates seed a lineage graph
  of goals → intents → facts/findings; a planner dispatches and workers execute
  (one intent = one AI session, read-only tools). Humans can drop intents into
  the graph at any time and stop/steer inline.
- **Blackboard mechanism** — every worker is injected with the same case
  blackboard (what sibling branches are chasing, what is confirmed, what is in
  doubt, what sits in the parking lot), so parallel branches never redo or
  collide.
- **Three convergence gates + parking lot** — fan-out / chapter / case budget
  gates hard-cap chain explosion; over-budget leads are not dropped but parked
  on the books, and only a human can expand or dismiss them.
- **Chain of custody never breaks** — originals live in a read-only vault
  (SHA256 content-addressed); every judgement is anchored to "host + source +
  line number + SHA256"; all operations go into a hash-chained audit log.
- **Human in the loop** — rule hits, operator findings and AI conclusions all
  land in review queues; bulk AI/rule-derived intents hang at an approval gate
  until a human approves; the UI deliberately avoids "confirm"-style wording.
- **Two report shapes** — a structured report generated from templates with
  zero LLM and full lineage backtracking; an AI-drafted narrative report as a
  separately-metered opt-in. The final verdict stays human.
- **Multi-user & no egress by default** — admin/operator roles with login
  lockout; data never leaves the machine, no telemetry; AI egress is the only
  data exit and it is off by default.
- **Two generations of battle-tested operator families, fused** — the log-level
  family (SuoTu: rate spikes / periodic beacons / composite-key outliers /
  rare-value cross-key / multi-step chains) and the host-level family
  (TreeCourt: auth chains / persistence / process masquerading / credential
  surface), both hardened on real cases, merged into 15 applicability-domain
  operators (web/host/cross). Numeric semantics were cross-validated
  case-by-case against the original Python engines — deterministic computation
  that never passes through an LLM, is re-runnable, and cannot hallucinate.

## Security statement & disclaimer (read me first)

**Doubt everything reasonably — including this tool's output.**

- **This tool is only for authorized security analysis, incident response and
  forensics.** You must hold legal authorization over whatever you analyze;
  the author accepts no liability for misuse.
- **Everything produced by rules, statistics, operators or AI is a
  "candidate"** and does not constitute a final attribution of any party. The
  platform does not endorse your conclusions — the human does. Any conclusion
  reached with this tool's assistance should be independently re-verified
  against the original evidence before being relied upon.
- **Data never leaves the machine**: everything (case DB / vault / accounts)
  lives in the runtime data directory; no telemetry, no callbacks. AI egress is
  the only data exit and it is off by default: enabling it requires a manual
  gate and a key; keys are stored AES-GCM-encrypted or supplied via environment
  variables, never in plaintext in the database.
- **Evidence integrity is a discipline, not a feature**: the read-only vault,
  SHA256 verification and the hash-chained audit log prove "the platform did not
  alter the data" — they cannot prove "the data itself is genuine". The
  credibility of collection and hand-over remains a human responsibility.
- This software is provided "as is", without warranties of any kind (see
  LICENSE). A security tool is itself an attack surface: follow the binding and
  password discipline in docs/DEPLOY.md, and replace every default/placeholder
  password.

## Recommended hardware

From measured runs, not extrapolation:

| Scenario | Spec | Measured anchor |
|---|---|---|
| Minimal (small cases / trial) | 4C / 8G / SSD | A 4-core VM ran a full ransomware case: 1,943 sources, 2.2M events |
| Recommended (daily IR) | 8C / 16G / NVMe | Parsing and scanning scale linearly with cores |
| Comfortable (large cases / parallel) | 16C / 16G+ / NVMe | 16-core VPS: a 1.5 GB package ingested in 335 s, zero bad lines |

- Disk: budget ~3× package size per case (vault + event store + indexes);
  100 GB holds roughly 20 mid-size cases. See docs/USAGE.md for
  archive/delete strategy.
- ClickHouse memory is capped at 8 GB by default (tunable in compose) to keep
  large scans from OOMing the box.
- Bandwidth only matters at upload: a 1.5 GB package over 25 Mbps takes about
  8 minutes; analysis itself is local.

## Three core principles

1. **Humans hold the verdict** — rule hits, operator findings and AI
   conclusions all land in a review queue awaiting human ruling. The UI
   deliberately avoids "confirm"-style wording.
2. **Chain of custody never breaks** — originals live in a read-only vault
   (SHA256 content-addressed); every judgement is anchored to "host + source +
   line number + SHA256"; all operations go into a hash-chained audit log.
3. **Honest, never silent** — not found, not covered, budget exhausted, data
   missing: all reported as-is. No silent gaps, no hard-coded conclusions.

## Architecture (one picture)

```
Collectors (separate projects): WinInfoSC.bat / LinuxSC.sh — field collection,
        │  zipped and shipped back
        │  HTTPS chunked upload + resume + SHA256 reconciliation
        ▼
┌─ fengtu server (single Go binary, frontend embedded, zero external assets) ─┐
│  ingress   upload intake / validation / registration                       │
│  ingest    parse pipeline (line logs via desc YAML descriptors;            │
│            evtx/hive/MFT/Prefetch/lnk/USN/EFU/JumpList/browser/SRUM via    │
│            native Go parsers)                                              │
│  review    rule engine (configs/rules YAML) + operators (configs/operators)│
│  intent    intent-chain engine: planner dispatches + workers execute       │
│            (one intent = one AI session, read-only tools); playbooks are   │
│            intent-chain templates (configs/playbooks)                      │
│  agentloop thin AI shell: egress gate / budget breaker / audit anchors     │
│  kb        heuristic knowledge base (configs/kb built-in + user entries,   │
│            injected per case)                                              │
│  web       HTTP API (net/http) + embedded frontend (React/Vite, go:embed)  │
└─────────────────────────────────────────────────────────────────────────────┘
        │                │                    │
        ▼                ▼                    ▼
  PostgreSQL 16    ClickHouse 25.x      data/ directory (local disk)
  cases/users/     events/entities      vault/  read-only originals
  audit chain      (columnar)           tmp/    upload staging
                                        workspace/ per-case workspaces
```

## Quick start (Docker Compose, recommended)

Requirements: Docker (tested on 29.x) + compose v2. One stack, three services:
the fengtu single binary (frontend embedded into the image) + PostgreSQL 16 +
ClickHouse 25.8.

```bash
# 1) Configure (the password string must match in three places:
#    POSTGRES_PASSWORD = the password segment of FENGTU_PG;
#    CLICKHOUSE_PASSWORD = FENGTU_CH_PASS; default bind 127.0.0.1 = local only)
cp .env.example .env && chmod 600 .env && $EDITOR .env

# 2) Build and start (Go dependencies are vendored — zero network fetches
#    at build time; in mainland China you can add
#    --build-arg NPM_REGISTRY=https://registry.npmmirror.com)
docker compose build
docker compose up -d

# 3) First-run admin: open http://127.0.0.1:8200 and follow the wizard
#    (one-time only; password ≥8 chars with letters+digits)
```

Full environment variable reference, bare-metal systemd deployment, upgrade and
backup procedures: `docs/DEPLOY.md` (Chinese).

## Feature map (screenshots)

> All screenshots were taken on a **fully synthetic demo instance**: case names
> `demo-*`, hosts `DEMO-WIN01` / `demo-lnx01`, and RFC5737 documentation IPs
> (203.0.113.x / 198.51.100.x) only — no real case data. The demo instance ran
> with the AI egress gate closed (zero token spend), so the approvals and
> parking-lot pages show their honest empty states. UI language is Chinese.

### Overview

Login & first-run wizard — the one-time admin bootstrap on first deploy, then
just the login gate (lockouts go to the audit chain).

![Login](docs/screenshots/01-login.png)

Dashboard — cases / sources / candidates / pending verdicts / pending approvals
at a glance, plus 7-day activity and case-status distribution.

![Dashboard](docs/screenshots/02-dashboard.png)

Task ledger — per-case type, status, source/candidate/pending counts, with the
live audit-chain stream on the right.

![Task list](docs/screenshots/03-tasks.png)

New-case wizard — type / background templates / multi-package upload / goal
presets / KB picks; creating jumps straight into the case page.

![New case wizard](docs/screenshots/04-new-case.png)

Global findings — cross-case candidate feed with severity / status / case
filters, each entry carrying an evidence grade.

![Global findings](docs/screenshots/18-findings.png)

### Case workbench

Explore chain — the intent lineage graph grows frame by frame (five node
types, five colors); the live feed streams on the right rail, and humans can
add intents or stop/steer inline.

![Explore chain & live feed](docs/screenshots/05-case-graph.png)

Candidate findings — rule/operator hits anchored to "source + line number";
accept/dismiss is a human ruling (concurrent CAS), and a hit is not a verdict.

![Candidate findings](docs/screenshots/06-candidates.png)

Content tree — the collection package tree with raw-text recall (line-number
anchors); anchors in candidate cards and chat jump straight here.

![Content tree](docs/screenshots/07-tree.png)

Search — full text + field conditions + time window + multi-source;
sub-second to seconds at 30M rows, measured.

![Search](docs/screenshots/08-search.png)

Timeline — all sources aggregated into hour buckets; sources without
timestamps are listed separately and honestly excluded from time windows.

![Timeline](docs/screenshots/09-timeline.png)

### Convergence & human review

Approval gate — bulk AI/rule-derived execution intents hang on creation and
only run after human approval; approvals and rejections go into the
hash-chained audit log (screenshot shows the honest empty state of the zero-AI
demo instance).

![Approvals](docs/screenshots/10-approvals.png)

Parking lot — leads held by the budget gates stay on the books with the
three-gate ledger in view; expanding or discarding is always a human decision
(also an honest empty state).

![Parking lot](docs/screenshots/11-parking.png)

Blackboard — a real-time four-section read-only view of case state (confirmed
facts / doubts / live intents / parking), the same copy injected into every
worker.

![Blackboard](docs/screenshots/12-blackboard.png)

Report — the structured report is template-generated with no LLM:
conclusions first + per-chapter findings + lineage backtracking + Markdown
download; the final verdict stays human.

![Structured report](docs/screenshots/13-report.png)

### Collaboration & administration

Workspace — a per-case isolated file manager for supplementary material
(inline text editing, writes audited), physically separated from the vault,
read-only to AI sessions.

![Workspace](docs/screenshots/14-workspace.png)

Knowledge base — 32 built-in heuristic methodology entries plus user entries,
injected into AI per case by explicit selection, never wholesale.

![Knowledge base](docs/screenshots/15-kb.png)

System settings — the AI master egress switch (off by default; off = 403 for
any vendor call), keys stored AES-GCM-encrypted and never echoed, budget gates
/ concurrency / proxy / web search in one place.

![System settings](docs/screenshots/16-settings.png)

User management — admin/operator roles with login lockout and backend
self-harm protection.

![User management](docs/screenshots/17-users.png)

### Coverage & status (text)

| Feature | Status | Entry |
|---|---|---|
| Case wizard (type/background/multi-package upload/intent presets/KB picks) | ✅ | sidebar "new IR task" |
| Upload intake (chunked/resume/hash reconciliation/collection-manifest check) | ✅ | wizard upload card |
| Parse pipeline (desc line-based + 12 native Windows parsers + LinuxSC packages) | ✅ (Windows coverage in docs/coverage-matrix.md) | automatic after upload |
| Intent-chain investigation (planner/worker + 14 playbook templates) | ✅ | case page "explore chain" tab |
| Live feed (real-time situational stream, inline stop/steer) | ✅ (no history replay; empty after restart — honest) | case page right rail |
| Approval gate (bulk AI/rule-derived intents require human approval) | ✅ | case page "approvals" tab |
| Parking lot (derived leads held by the budget gate; human expands or discards) | ✅ | case page "parking lot" tab |
| Candidate findings + ruling (accept/dismiss, concurrent CAS 409) | ✅ | case page "findings" tab |
| Content tree (collection-package tree + raw-text recall + format re-judgement) | ✅ | case page "content tree" tab |
| Search (full text / field conditions / time window / multi-source) | ✅ (sub-second to seconds at 30M rows, measured) | case page "search" tab |
| Timeline (hour-bucket density + separate lane for tz-less sources) | ✅ | case page "timeline" tab |
| Workspace (per-case isolated file manager, AI-readable) | ✅ | case page "workspace" tab |
| Knowledge base (built-in + user entries, injected per case) | ✅ | case page "KB" tab |
| Operational constraints (human red lines injected into workers, fail-closed) | ✅ | case page "constraints" tab |
| Rules/operators (signature rules + operators, swappable YAML data files) | ✅ (inventory in docs/operator-inventory.md) | runs with one-click analysis |
| Report (templated skeleton + lineage subgraph + markdown download) | ✅ (no LLM; final verdict stays human) | case page "report" tab |
| Multi-user (admin/operator tiers + login lockout) | ✅ (no per-row case isolation — team-shared by design) | /system/users |
| Seal export/import (single zip, cross-instance migration, per-file hash reconciliation) | ✅ | case header "export seal" |
| AI egress (DeepSeek default, OpenAI-format swappable) | ⚠️ off by default (egress gate); requires manual enabling + key | /system/settings |

Known boundaries (honest):

- Intents stuck in `running` after a restart are not auto-reclaimed (workers die
  with the process); the live feed and task ledger are in-memory and empty after
  restart (result data is unaffected).
- The intent graph renders SVG frame by frame; cases with hundreds of nodes are
  untested.
- Some LinuxSC collection faces (init.d / xdg-autostart / rotated archives …)
  are registered as searchable raw text without field extraction yet (deferred
  items listed in docs/operator-inventory.md); coverage grows per release.

## Configuration essentials

- **One password string in three places**: `POSTGRES_PASSWORD` = the password
  segment of `FENGTU_PG`; `CLICKHOUSE_PASSWORD` = `FENGTU_CH_PASS`. Replace
  every placeholder.
- **Binding discipline**: the web port binds `127.0.0.1` by default
  (`FENGTU_BIND_IP`); expose to a team via an internal address or a TLS reverse
  proxy, and set `FENGTU_COOKIE_SECURE=true` behind TLS.
- **AI egress is off by default**: without a key, AI endpoints answer 503 and
  the egress gate 403 — everything else works; enable it in
  `/system/settings`. Keys are stored AES-GCM-encrypted or supplied via
  environment variables.
- **Memory fuses**: ClickHouse `deploy/ch-limits.xml` (8 GB default — tune to
  your machine) stacks with the application-level 4 GB per-session fuse.
- All 24 `FENGTU_*` variables are documented at the top of
  `cmd/fengtu/main.go` and in `docs/DEPLOY.md` (Chinese).

## Build from source

Requirements: Go ≥ 1.26, Node.js 18+ (frontend build only; the output is
embedded into the binary).

```bash
cd frontend && npm install && npm run build && cd ..
go build -o bin/fengtu ./cmd/fengtu
./bin/fengtu        # listens on 127.0.0.1:8200 by default; PG migrations run
                    # at startup and abort on failure
```

## Tests

```bash
go vet ./... && go test ./...      # backend (incl. golden-file comparisons, no real DB)
cd frontend && npm test            # frontend vitest (upload state machine, ruling UX, …)
```

Discipline: parsers are written against specs, not values; no concrete case data
may appear in code or tests (anti-overfitting gates are enforced by negative
fixture tests); golden files are generated by an independent Python reference
engine and compared offline.

## Documentation

- `DESIGN.md` — platform design book (positioning / choices / intent chains /
  performance contract / milestones) (Chinese)
- `docs/DEPLOY.md` — from-scratch deployment manual (Chinese)
- `docs/USAGE.md` — operator's manual, login to report (Chinese)
- `docs/EXTEND.md` — configuration extension manual: desc/rules/operators/
  playbooks/kb (Chinese)
- `docs/coverage-matrix.md` — WinInfoSC collection-item parse coverage matrix
  (Chinese)
- `docs/operator-inventory.md` — operator/rule inventory (Chinese)

## Special thanks

- **[ARTEX](https://github.com/Autumn-27/ARTEX)** — the inspiration for the
  intent-chain interaction and layout design: the explore-chain graph, live
  feed, blackboard and convergence-gate interaction patterns were all inspired
  by ARTEX (backend semantics and data models are FengTu's own implementation).
- `testdata/parsers/NTUSER.DAT` comes from velocidex/regparser (Apache-2.0);
  the golden-file comparison baseline is generated by the independent SuoTu
  Python engine (same author).

## License

[Apache License 2.0](./LICENSE) (Copyright 2026 ye-mengwen). If you build on
FengTu, keep the copyright notice and mark your changes prominently.
