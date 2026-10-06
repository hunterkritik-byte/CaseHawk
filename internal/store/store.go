package store

import (
    "context"
    "database/sql"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"
    _ "github.com/jackc/pgx/v5/stdlib"
)

func Open(dsn string) (*sql.DB, error) {
    db, err := sql.Open("pgx", dsn)
    if err != nil { return nil, err }
    ctx, cancel := context.WithCancel(context.Background()); defer cancel()
    if err := db.PingContext(ctx); err != nil { _ = db.Close(); return nil, err }
    return db, nil
}

func Migrate(db *sql.DB) error {
    _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','investigator','evidence_officer','viewer')),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY,
    case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS network_indicators (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'unknown',
    provider TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'unknown',
    notes TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_indicators_case ON network_indicators(case_id);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON network_indicators(value);
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    target_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at, id);
CREATE OR REPLACE FUNCTION casehawk_block_audit_mutation() RETURNS trigger AS E'BEGIN\n    RAISE EXCEPTION ''audit_events is append-only'';\nEND;' LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION casehawk_block_audit_mutation();
`)
    return err
}

func VerifyAuditChain(db *sql.DB) error {
    rows,err:=db.Query("SELECT id,case_id,action,actor,target_id,metadata,prev_hash,event_hash,created_at FROM audit_events ORDER BY id ASC")
    if err!=nil{return err};defer rows.Close()
    prev:=""
    for rows.Next(){
        var id int64;var caseID,action,actor,target,storedPrev,storedHash string;var metadata []byte;var created time.Time
        if err:=rows.Scan(&id,&caseID,&action,&actor,&target,&metadata,&storedPrev,&storedHash,&created);err!=nil{return err}
        if storedPrev!=prev{return fmt.Errorf("audit chain broken at event %d: previous hash mismatch",id)}
        sum:=sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",prev,caseID,action,actor,target,string(metadata),created.UTC().Format(time.RFC3339Nano))))
        if hex.EncodeToString(sum[:])!=storedHash{return fmt.Errorf("audit chain broken at event %d: event hash mismatch",id)}
        prev=storedHash
    }
    return rows.Err()
}
