ALTER TABLE audit_events ADD COLUMN sequence INTEGER;
ALTER TABLE audit_events ADD COLUMN hash_algorithm TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN previous_event_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT '';

CREATE TABLE audit_chain_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    hash_algorithm TEXT NOT NULL,
    latest_sequence INTEGER NOT NULL,
    latest_event_hash TEXT NOT NULL,
    checkpoint_sequence INTEGER NOT NULL,
    checkpoint_event_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
