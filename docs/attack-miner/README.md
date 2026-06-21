# Attack-Miner: Classical A/D Clustering & Synthesis

**Attack-miner** is a fully-automated, no-LLM classical attack and defense mining system built into Tulip. It clusters similar flows by their network structure, synthesizes typed templates and gated replication payloads, and synthesizes defensive firewall rules—all without external language models.

## End-to-End Data Flow

```
Flows (live from assembler)
  ↓
[MINECORE] Normalize + MinHash clustering
  ↓
Cluster tags: cluster:<service>:<id>
  ↓
[API] /clusters summary, /templates, /flows_tag_bulk
  ↓
Frontend: ClustersView (dashboard w/ click-to-filter)
  ├─→ [REPLICATOR] Template instantiation + NOP-proof gate + fan-out (OFFENSE)
  │       ↓
  │   Template + variable slots → sploit instances
  │       ↓
  │   Fire at NOP (proof) → fire at targets (arm-gated) → farm submission
  │
  └─→ [PATCH-ENGINE] Regex synthesis + zero-benign gate + firegex deploy (DEFENSE)
        ↓
      Template const tokens → candidate anchors
        ↓
      Refuse if anchor appears in benign/checker samples
        ↓
      Push regex to firegex INACTIVE (arm-gated to enable)
```

## Components

| Component | Language | Responsibility |
|-----------|----------|-----------------|
| **minecore** | Go | Stream clustering engine: live-poll flows, compute MinHash signatures, leader-cluster by LSH, tag cluster membership, synthesize typed templates, measure per-service heat (SLA/stolen flags), persist state |
| **api+cockpit** | Python/React | REST routes over `mine.*` schema (`/clusters`, `/templates`, `/flow_tag`, `/flows_tag_bulk`); React ClustersView for cluster exploration and tag navigation |
| **replicator** | Python | Template instantiation + actuation for offense: fetch live flagIds, fill variable slots, NOP-proof before fan-out, fire at targets (arm-gated), extract flags from responses, submit to farm |
| **patch-engine** | Python | Template-to-rule synthesis + actuation for defense: regex synthesis refusing SLA-killing anchors, push rules to firegex inactive, arm to enable, rollback to disable+delete |

### Minecore (Go) — `/home/rob/MadrHacks/tulip/services/go-importer/cmd/minecore/main.go`

**Clustering:**
- Polls flows from Timescale in bounded batches (default 512), within a time horizon (default 20 min)
- Normalizes flow data: flag + flagId masking, canonicalization
- Computes 128-bit MinHash signatures via `Featurize` (token+charclass hashing)
- LSH-indexed leader clustering: assigns each flow to the best-matching cluster by Jaccard ≥0.82 against either the medoid or frozen core
- Freezes cluster identity (core) once 3 members quorum reached
- Tags each flow: `cluster:<service>:<id>`
- Snapshots clusters every 60 sec for persistence across restarts

**Synthesis:**
- At quorum and when cluster size doubles: extracts member samples, aligns constant/variable segments via token-diff
- Classifies slots (const/flag/flagId/random) by value distribution + high-entropy test
- Enriches each slot with charclass (alphanumeric, byte range, etc) and example values
- Stores versioned templates in `mine.template` (service, cluster_id, json body)

**Heat:**
- Fetches scoreboard at startup, computes per-service heat: our lost flags, our stolen, total stolen, SLA status
- Used by patch-engine for SLA-aware gating

### API + Cockpit (Python/React)

**Routes:**
- `GET /clusters` — cluster summaries (service, id, count, flag_in, flag_out) with optional `since` filter
- `GET /templates` — all templates (service, cluster_id, tag, json body)
- `POST /flow_tag` — tag single flow
- `POST /flows_tag_bulk` — bulk tag by query (regex, IP subnet, port, time range)

**Frontend ClustersView** (`frontend/src/pages/ClustersView.tsx`):
- Table sorted by cluster size
- Columns: service, cluster id, member count, flag_in/out heat, template checkmark, tag
- Click to filter flows by cluster tag

### Replicator (Python) — `/home/rob/MadrHacks/tulip/services/replicator/app.py`

**API (control-plane, disarmed by default):**
- `GET /status` — armed state + proven sploits set
- `POST /arm`, `POST /disarm` — manual gate (the human control point)
- `POST /nop_proof` — fire template at NOP (if NOP-proof, marks sploit proven)
- `POST /fanout` — fire proven sploit at all targets (requires arm + proof)

**Actuation:**
- **NOP-proof gate:** Refuses any sploit not proven against NOP (structural anti-leak guarantee)
- **Anti-leak structural gate:** Computes allowed targets as all teams except ours; refuses to fire at own team
- **FlagId fetching:** Always re-fetches live flagIds per (service, team) so a flagId never leaks between teams
- **Response parsing:** Extracts flags via regex, submits to farm (never direct to gameserver)
- Template instantiation: fills variable slots (flagId from live fetch, random nonces, etc.)

### Patch-Engine (Python) — `/home/rob/MadrHacks/tulip/services/patch-engine/app.py`

**API (control-plane, disarmed by default):**
- `GET /status` — armed state
- `POST /arm`, `POST /disarm` — manual gate
- `POST /propose` — synthesize rule from template consts + benign samples, push inactive to firegex, returns regex_id
- `POST /arm_rule` — enable (only if armed)
- `POST /rollback` — disable + delete

**Synthesis + Safety Gates** (`services/patch-engine/synth.py`):
- Extracts candidate anchors from template constant tokens (length ≥4, deduplicated, sorted by specificity)
- For each anchor: tests if it matches ANY benign/checker sample
- **Zero-benign gate:** Refuses synthesis (returns None) if every candidate anchor appears in some benign sample
- Escapes final anchor as regex and pushes to firegex **INACTIVE** (arm-gated to flip live)
- **Rollback:** Flips rule back to inactive + deletes from firegex

## Safety Model

Both **replicator** and **patch-engine** ship **DISARMED by default** (env vars `REPLICATOR_ARMED=false`, `PATCH_ENGINE_ARMED=false`). Arming is the human control gate.

### Replicator Safety (Offense)

1. **Structural anti-leak:** Allowlist computed as `[1..team_count] - {our_team_id}`, refusing own team structurally
2. **NOP-proof before fan-out:** Any sploit must first capture a flag against NOP; only then can it fan-out
3. **FlagId isolation:** Live-fetched per target so a flagId never flows to the wrong team
4. **Farm submission:** All flags go through the farm API (with auth token), never direct to gameserver
5. **Arming:** Human must call `POST /arm` on the replicator control API to enable any traffic

### Patch-Engine Safety (Defense)

1. **Zero-benign-match gate:** Synthesis refuses any anchor seen in benign or SLA-checker traffic (mandatory, conservative)
2. **Rules created INACTIVE:** Proposed rules land in firegex disabled, preventing accidental matching on checker flows
3. **Arming to enable:** Only when `armed=true` can `POST /arm_rule` flip a rule live; default is false
4. **Rollback reflex:** Engine disables + deletes rules if SLA check fails on that service
5. **Gating in synthesis:** If no anchor passes zero-benign gate, returns None (rule not created)

## Deployment

Docker compose (`/home/rob/MadrHacks/tulip/compose.yml`):

```yaml
  minecore:
    environment:
      TIMESCALE: ${TIMESCALE}
      # Optional: MINECORE_HORIZON=20m (default), MINECORE_POLL_BATCH=512, MINECORE_POLL_INTERVAL=1s

  replicator:
    environment:
      REPLICATOR_ARMED: "false"        # START DISARMED
      FARM_URL: ${FARM_URL}
      AD_INFRA_CONFIG_DIR: /config     # Mount game.yml + farm.yml here
    volumes:
      - ${AD_INFRA_CONFIG_DIR}:/config:ro

  patch-engine:
    environment:
      PATCH_ENGINE_ARMED: "false"      # START DISARMED
      FIREGEX_URL: ${FIREGEX_URL}
      FIREGEX_PASSWORD: ${FIREGEX_PASSWORD}
```

**Env Vars & Config:**

- **TIMESCALE:** PostgreSQL connection string (shared by minecore, api, replicator if fetching schema)
- **FARM_URL:** Farm API endpoint for flag submission (replicator)
- **FIREGEX_URL, FIREGEX_PASSWORD:** Firegex control API (patch-engine)
- **AD_INFRA_CONFIG_DIR:** Directory containing `game.yml` + `farm.yml` (replicator reads team_id, ip_format, flag_regex, flagIds URL, farm token here)
- **REPLICATOR_ARMED, PATCH_ENGINE_ARMED:** Boolean env vars; default false

## Status: What's Built & What's Not

### Done (Phases 0, 1, 2, 5, and Much of 4, 7, 8)

**Phase 0 (Data):**
- Live flow assembly and storage in Timescale ✓

**Phase 1 (Clustering):**
- MinHash signature + LSH indexing ✓
- Leader clustering with frozen-core identity anchor ✓
- Cluster tagging and persistence ✓

**Phase 2 (Synthesis):**
- Template extraction via token-diff alignment ✓
- Slot typing (const/flag/flagId/random) + charclass enrichment ✓
- Template versioning and persistence ✓
- Per-service heat (SLA, stolen flags) from scoreboard ✓

**Phase 4 (Offense) — Mostly Done:**
- Template instantiation with variable slot filling ✓
- NOP-proof gating ✓
- Anti-leak structural target allowlist ✓
- Farm submission (flagId isolation per target) ✓
- Flask control API (arm/disarm/nop_proof/fanout) ✓

**Phase 5 (Defense) — Mostly Done:**
- Regex synthesis with zero-benign-match gate ✓
- Firegex integration (add/activate/rollback) ✓
- Flask control API (arm/disarm/propose/arm_rule/rollback) ✓

**Phase 7 (Frontend/Cockpit) — Partial:**
- Cluster dashboard (ClustersView) with click-to-filter ✓
- Template display in cluster view ✓

**Phase 8 (Monitoring) — Partial:**
- Per-cluster heat display (flag_in, flag_out) in frontend ✓
- Scoreboard polling in minecore ✓

### Not Yet Built

- **Checker-discrimination model:** Currently synthesizes anchors absent from benign samples only; does not yet learn patterns specific to checker vs. attack flows
- **Semi-supervised propagation:** Templates not yet used to label related flows or suggest new attacks
- **Live scoreboard polling wiring:** Minecore reads scoreboard at startup; no continuous update loop
- **Template workbench UX:** No frontend for experimenting with template variants, slot overrides, or manual synthesis
- **Autonomy / Audit layer:** All actuator gates are manual (arm/disarm); no autonomous scoring, risk assessment, or decision logic yet
- **Live patch-engine SLA monitoring:** Patch-engine has rollback logic but no active SLA polling integration

## Architecture Files

Key source files:

- **Minecore:** `services/go-importer/cmd/minecore/main.go`, `internal/pkg/mine/{mine.go, cluster.go, template.go, synth.go, heat.go, normalize.go, features.go, lsh.go, align.go, schema.go, persist.go}`
- **API:** `services/api/webservice.py` (lines 134–226 for new routes)
- **Frontend:** `frontend/src/pages/ClustersView.tsx`
- **Replicator:** `services/replicator/{app.py, actuate.py, instantiate.py, config.py}`
- **Patch-Engine:** `services/patch-engine/{app.py, deploy.py, synth.py, firegex_client.py}`
- **Database schema:** `services/go-importer/internal/pkg/mine/schema.go` (creates `mine.*` tables)
- **Deployment:** `compose.yml` (lines 122–155)
