-- Hamza Record store (§6.6). Content-free by invariant (ADR 0004): accounting +
-- Findings (rule + action) only, never raw prompts, code, or secret values.
-- Rows are immutable: written once, never mutated.

CREATE TABLE IF NOT EXISTS schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version   TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_metadata (singleton, version) VALUES (1, 'hamza-db/v2');

CREATE TABLE IF NOT EXISTS turns (
    turn_id               TEXT PRIMARY KEY,
    session_id            TEXT,
    agent                 TEXT    NOT NULL,
    provider              TEXT    NOT NULL,
    requested_model       TEXT,
    served_model          TEXT,
    status                TEXT,
    input_tokens          INTEGER NOT NULL,
    cached_input_tokens   INTEGER NOT NULL,
    uncached_input_tokens INTEGER NOT NULL,
    output_tokens         INTEGER NOT NULL,
    reasoning_tokens      INTEGER NOT NULL,
    total_tokens          INTEGER NOT NULL,
    tool_calls            INTEGER NOT NULL,
    action                TEXT    NOT NULL,
    duration_ms           INTEGER NOT NULL,
    ts                    TEXT    NOT NULL,
    request_id            TEXT,
    request_bytes_received INTEGER,
    request_bytes_inspected INTEGER,
    request_bytes_egressed INTEGER,
    record_role           TEXT NOT NULL DEFAULT 'STANDARD',
    recovery_id           TEXT,
    parent_turn_id        TEXT,
    recipe_id             TEXT,
    recipe_version        INTEGER,
    workflow_profile_id   TEXT,
    workflow_profile_version INTEGER,
    continuation_status   TEXT,
    continuation_reason   TEXT,
    task_path             TEXT,
    task_status           TEXT,
    request_bytes_withheld INTEGER,
    masked_value_count    INTEGER,
    -- Tamper-evident hash chain (PRD R4.5, ADR 0015). Each row commits to the
    -- previous row's entry_hash, so any after-the-fact edit breaks the chain from
    -- that point on. Content-free: v5 covers detector runs and masked-value count.
    seq                   INTEGER,
    posture               TEXT,
    config_fingerprint    TEXT,
    hash_version          TEXT,
    prev_hash             TEXT,
    entry_hash            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    turn_id  TEXT NOT NULL,
    detector TEXT NOT NULL,
    rule     TEXT NOT NULL,
    action   TEXT NOT NULL,
    FOREIGN KEY (turn_id) REFERENCES turns (turn_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_turn ON findings (turn_id);

CREATE TABLE IF NOT EXISTS detector_runs (
    turn_id             TEXT NOT NULL,
    detector            TEXT NOT NULL,
    detector_version    TEXT NOT NULL,
    status              TEXT NOT NULL,
    reason              TEXT,
    received_segments   INTEGER NOT NULL,
    inspected_segments  INTEGER NOT NULL,
    received_bytes      INTEGER NOT NULL,
    inspected_bytes     INTEGER NOT NULL,
    duration_micros     INTEGER NOT NULL,
    finding_count       INTEGER NOT NULL,
    FOREIGN KEY (turn_id) REFERENCES turns (turn_id),
    UNIQUE (turn_id, detector)
);

CREATE INDEX IF NOT EXISTS idx_detector_runs_turn ON detector_runs (turn_id);

CREATE TABLE IF NOT EXISTS edm_events (
    turn_id        TEXT NOT NULL,
    registry       TEXT NOT NULL,
    distinct_count INTEGER NOT NULL,
    action         TEXT NOT NULL,
    FOREIGN KEY (turn_id) REFERENCES turns (turn_id)
);

CREATE INDEX IF NOT EXISTS idx_edm_events_turn ON edm_events (turn_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_edm_events_turn_registry
    ON edm_events (turn_id, registry);

-- Chain walks read rows in seq order (one Turn occupies exactly one seq).
CREATE UNIQUE INDEX IF NOT EXISTS idx_turns_seq ON turns (seq);
CREATE INDEX IF NOT EXISTS idx_turns_recovery ON turns (recovery_id);
CREATE INDEX IF NOT EXISTS idx_turns_parent ON turns (parent_turn_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_turns_derived_parent
    ON turns (parent_turn_id) WHERE record_role = 'DERIVED';

-- Signed, terminal workflow evidence. One recovery scope accepts at most one
-- outcome. Exact signed replay is handled idempotently by the repository.
CREATE TABLE IF NOT EXISTS recovery_outcomes (
    recovery_id             TEXT PRIMARY KEY,
    outcome_status          TEXT NOT NULL,
    agent                   TEXT NOT NULL,
    agent_version           TEXT NOT NULL,
    workflow_profile_id     TEXT NOT NULL,
    workflow_profile_version INTEGER NOT NULL,
    acceptance_gate_id      TEXT NOT NULL,
    started_at              TEXT NOT NULL,
    completed_at            TEXT NOT NULL,
    signature_version       TEXT NOT NULL,
    signature               TEXT NOT NULL,
    seq                     INTEGER NOT NULL UNIQUE,
    hash_version            TEXT NOT NULL,
    prev_hash               TEXT NOT NULL,
    entry_hash              TEXT NOT NULL
);

-- A conflicting terminal outcome is rejected. Only its fixed, content-free gap
-- class is retained. The recovery id and conflicting evidence are not duplicated.
CREATE TABLE IF NOT EXISTS evidence_integrity_gaps (
    gap_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    observed_at TEXT NOT NULL
);
