ALTER TABLE audit_events ADD COLUMN chain_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_events ADD COLUMN hash_algorithm TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN previous_event_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT '';
CREATE TABLE audit_chain_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tail_chain_index INTEGER NOT NULL,
    tail_event_id TEXT NOT NULL,
    tail_event_hash TEXT NOT NULL,
    total_event_count INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT INTO audit_chain_state (id, tail_chain_index, tail_event_id, tail_event_hash, total_event_count, updated_at) VALUES (1, 0, '', '', 0, '1970-01-01T00:00:00Z');
CREATE TABLE audit_chain_checkpoints (
    id TEXT PRIMARY KEY,
    through_chain_index INTEGER NOT NULL UNIQUE,
    through_event_id TEXT NOT NULL,
    through_event_hash TEXT NOT NULL,
    retention_cutoff TEXT NOT NULL,
    created_at TEXT NOT NULL
);
