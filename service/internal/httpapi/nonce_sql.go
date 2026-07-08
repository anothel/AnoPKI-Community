// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"context"
	"database/sql"
	"time"
)

type SQLACMENonceStore struct {
	db     *sql.DB
	driver string
}

const (
	sqliteExpiredNonceCleanupQuery   = "DELETE FROM acme_nonces WHERE expires_at <= ?"
	sqliteInsertNonceQuery           = "INSERT INTO acme_nonces (nonce, issued_at, expires_at) VALUES (?, ?, ?)"
	sqliteConsumeNonceQuery          = "DELETE FROM acme_nonces WHERE nonce = ? AND expires_at > ?"
	postgresExpiredNonceCleanupQuery = "DELETE FROM acme_nonces WHERE expires_at <= $1"
	postgresInsertNonceQuery         = "INSERT INTO acme_nonces (nonce, issued_at, expires_at) VALUES ($1, $2, $3)"
	postgresConsumeNonceQuery        = "DELETE FROM acme_nonces WHERE nonce = $1 AND expires_at > $2"
)

func NewSQLACMENonceStore(db *sql.DB, driver string) *SQLACMENonceStore {
	return &SQLACMENonceStore{db: db, driver: driver}
}

func (s *SQLACMENonceStore) Issue(ctx context.Context, nonce string, issuedAt time.Time, expiresAt time.Time) error {
	if s.driver == "sqlite" {
		if _, err := s.db.ExecContext(ctx, sqliteExpiredNonceCleanupQuery, issuedAt); err != nil {
			return err
		}
		_, err := s.db.ExecContext(ctx, sqliteInsertNonceQuery, nonce, issuedAt, expiresAt)
		return err
	}
	if _, err := s.db.ExecContext(ctx, postgresExpiredNonceCleanupQuery, issuedAt); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, postgresInsertNonceQuery, nonce, issuedAt, expiresAt)
	return err
}

func (s *SQLACMENonceStore) Consume(ctx context.Context, nonce string, now time.Time) (bool, error) {
	query := postgresConsumeNonceQuery
	if s.driver == "sqlite" {
		query = sqliteConsumeNonceQuery
	}
	result, err := s.db.ExecContext(ctx, query, nonce, now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}
