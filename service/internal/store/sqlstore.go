// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

type SQLStore struct {
	db *sql.DB
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type sqlScanner interface {
	Scan(dest ...any) error
}

type sqlRepository struct {
	exec sqlExecutor
}

var _ Repository = (*SQLStore)(nil)
var _ Repository = sqlRepository{}

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) WithinTx(ctx context.Context, fn func(Repository) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	repo := sqlRepository{exec: tx}
	if err := fn(repo); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	return s.repository().CreateIdentity(ctx, identity)
}

func (s *SQLStore) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	return s.repository().GetIdentity(ctx, id)
}

func (s *SQLStore) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	return s.repository().ListIdentities(ctx)
}

func (s *SQLStore) ListIdentitiesQuery(ctx context.Context, query IdentityQuery) ([]domain.Identity, error) {
	return s.repository().ListIdentitiesQuery(ctx, query)
}

func (s *SQLStore) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	return s.repository().CreateIssuer(ctx, issuer)
}

func (s *SQLStore) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	return s.repository().GetIssuer(ctx, id)
}

func (s *SQLStore) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	return s.repository().ListIssuers(ctx)
}

func (s *SQLStore) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	return s.repository().CreateOCSPResponder(ctx, responder)
}

func (s *SQLStore) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	return s.repository().GetOCSPResponder(ctx, id)
}

func (s *SQLStore) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	return s.repository().ListOCSPRespondersByIssuer(ctx, issuerID)
}

func (s *SQLStore) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	return s.repository().GetActiveOCSPResponderByIssuer(ctx, issuerID)
}

func (s *SQLStore) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	return s.repository().UpdateOCSPResponderIfStatus(ctx, responder, currentStatus)
}

func (s *SQLStore) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	return s.repository().CreateNotificationEndpoint(ctx, endpoint)
}

func (s *SQLStore) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	return s.repository().GetNotificationEndpoint(ctx, id)
}

func (s *SQLStore) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	return s.repository().ListNotificationEndpoints(ctx)
}

func (s *SQLStore) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	return s.repository().UpdateNotificationEndpointIfStatus(ctx, endpoint, currentStatus)
}

func (s *SQLStore) CreateAPIKey(ctx context.Context, key domain.APIKey) error {
	return s.repository().CreateAPIKey(ctx, key)
}

func (s *SQLStore) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	return s.repository().GetAPIKey(ctx, id)
}

func (s *SQLStore) GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error) {
	return s.repository().GetAPIKeyByTokenHash(ctx, tokenHash)
}

func (s *SQLStore) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	return s.repository().ListAPIKeys(ctx)
}

func (s *SQLStore) UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	return s.repository().UpdateAPIKeyIfStatus(ctx, key, currentStatus)
}

func (s *SQLStore) repository() sqlRepository {
	return sqlRepository{exec: s.db}
}

func (r sqlRepository) WithinTx(ctx context.Context, fn func(Repository) error) error {
	return fn(r)
}

func addSQLStringCondition(args *[]any, conditions *[]string, column string, value string) {
	if value == "" {
		return
	}
	*args = append(*args, value)
	*conditions = append(*conditions, fmt.Sprintf("%s = $%d", column, len(*args)))
}

func appendSQLWhere(query *strings.Builder, conditions []string) {
	if len(conditions) == 0 {
		return
	}
	query.WriteString("\nWHERE ")
	query.WriteString(strings.Join(conditions, " AND "))
}

func appendSQLSort(query *strings.Builder, sortOrder string, createdAtColumn string, idColumn string) {
	if sortOrder == "desc" {
		query.WriteString(fmt.Sprintf("\nORDER BY %s DESC, %s DESC", createdAtColumn, idColumn))
		return
	}
	query.WriteString(fmt.Sprintf("\nORDER BY %s ASC, %s ASC", createdAtColumn, idColumn))
}

func appendSQLLimitOffset(query *strings.Builder, args *[]any, limit int, offset int) {
	if limit <= 0 {
		return
	}
	*args = append(*args, limit)
	query.WriteString(fmt.Sprintf("\nLIMIT $%d", len(*args)))
	if offset > 0 {
		*args = append(*args, offset)
		query.WriteString(fmt.Sprintf(" OFFSET $%d", len(*args)))
	}
}

func sqlJSONStringElementPattern(value string) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return "%" + string(encoded) + "%", nil
}

func (r sqlRepository) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	allowedDNSNames, err := marshalStringSlice(identity.AllowedDNSNames)
	if err != nil {
		return err
	}
	allowedIPAddresses, err := marshalStringSlice(identity.AllowedIPAddresses)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO identities (
	id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		identity.ID,
		string(identity.Type),
		identity.Name,
		identity.ExternalID,
		identity.Owner,
		identity.Team,
		identity.Service,
		identity.Environment,
		identity.DeploymentTarget,
		formatNullableSQLTime(identity.LastSeenAt),
		identity.MetadataJSON,
		allowedDNSNames,
		allowedIPAddresses,
		string(identity.Status),
		formatSQLTime(identity.CreatedAt),
		formatSQLTime(identity.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	identity, err := scanIdentity(r.exec.QueryRowContext(ctx, `
SELECT id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
FROM identities
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Identity{}, domain.ErrIdentityNotFound
	}
	if err != nil {
		return domain.Identity{}, err
	}
	return identity, nil
}

func (r sqlRepository) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
FROM identities
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	identities := make([]domain.Identity, 0)
	for rows.Next() {
		identity, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return identities, nil
}

func (r sqlRepository) ListIdentitiesQuery(ctx context.Context, query IdentityQuery) ([]domain.Identity, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
FROM identities`)
	args := make([]any, 0)
	conditions := make([]string, 0)
	addSQLStringCondition(&args, &conditions, "owner", query.Owner)
	addSQLStringCondition(&args, &conditions, "team", query.Team)
	addSQLStringCondition(&args, &conditions, "service", query.Service)
	addSQLStringCondition(&args, &conditions, "environment", query.Environment)
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "created_at", "id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	identities := make([]domain.Identity, 0)
	for rows.Next() {
		identity, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return identities, nil
}

func (r sqlRepository) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	distributionPoints, err := marshalStringSlice(issuer.CRLDistributionPoints)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO issuers (
	id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url, crl_distribution_points, trust_anchor, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)`,
		issuer.ID,
		issuer.Name,
		string(issuer.Kind),
		string(issuer.Status),
		issuer.ParentIssuerID,
		issuer.CertificatePEM,
		issuer.KeyRef,
		issuer.AIAURL,
		distributionPoints,
		issuer.TrustAnchor,
		formatSQLTime(issuer.CreatedAt),
		formatSQLTime(issuer.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	issuer, err := scanIssuer(r.exec.QueryRowContext(ctx, `
SELECT id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url, crl_distribution_points, trust_anchor, created_at, updated_at
FROM issuers
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Issuer{}, domain.ErrIssuerNotFound
	}
	if err != nil {
		return domain.Issuer{}, err
	}
	return issuer, nil
}

func (r sqlRepository) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url, crl_distribution_points, trust_anchor, created_at, updated_at
FROM issuers
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	issuers := make([]domain.Issuer, 0)
	for rows.Next() {
		issuer, err := scanIssuer(rows)
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, issuer)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return issuers, nil
}

func (r sqlRepository) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO ocsp_responders (
	id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		responder.ID,
		responder.IssuerID,
		responder.Name,
		string(responder.Status),
		responder.CertificatePEM,
		responder.KeyRef,
		formatSQLTime(responder.CreatedAt),
		formatSQLTime(responder.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	responder, err := scanOCSPResponder(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
FROM ocsp_responders
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	return responder, nil
}

func (r sqlRepository) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
FROM ocsp_responders
WHERE issuer_id = $1
ORDER BY created_at, id`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	responders := make([]domain.OCSPResponder, 0)
	for rows.Next() {
		responder, err := scanOCSPResponder(rows)
		if err != nil {
			return nil, err
		}
		responders = append(responders, responder)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return responders, nil
}

func (r sqlRepository) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	responder, err := scanOCSPResponder(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
FROM ocsp_responders
WHERE issuer_id = $1 AND status = $2
ORDER BY created_at DESC, id DESC
LIMIT 1`, issuerID, string(domain.OCSPResponderActive)))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	return responder, nil
}

func (r sqlRepository) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE ocsp_responders
SET issuer_id = $1,
	name = $2,
	status = $3,
	certificate_pem = $4,
	key_ref = $5,
	created_at = $6,
	updated_at = $7
WHERE id = $8 AND status = $9`,
		responder.IssuerID,
		responder.Name,
		string(responder.Status),
		responder.CertificatePEM,
		responder.KeyRef,
		formatSQLTime(responder.CreatedAt),
		formatSQLTime(responder.UpdatedAt),
		responder.ID,
		string(currentStatus),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := r.GetOCSPResponder(ctx, responder.ID); errors.Is(err, domain.ErrOCSPResponderNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	eventTypes, err := marshalStringSlice(endpoint.EventTypes)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO notification_endpoints (
	id, name, type, status, url, secret, event_types, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9
)`,
		endpoint.ID,
		endpoint.Name,
		string(endpoint.Type),
		string(endpoint.Status),
		endpoint.URL,
		endpoint.Secret,
		eventTypes,
		formatSQLTime(endpoint.CreatedAt),
		formatSQLTime(endpoint.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	endpoint, err := scanNotificationEndpoint(r.exec.QueryRowContext(ctx, `
SELECT id, name, type, status, url, secret, event_types, created_at, updated_at
FROM notification_endpoints
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NotificationEndpoint{}, domain.ErrNotificationEndpointNotFound
	}
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	return endpoint, nil
}

func (r sqlRepository) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, type, status, url, secret, event_types, created_at, updated_at
FROM notification_endpoints
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]domain.NotificationEndpoint, 0)
	for rows.Next() {
		endpoint, err := scanNotificationEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func (r sqlRepository) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	eventTypes, err := marshalStringSlice(endpoint.EventTypes)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE notification_endpoints
SET name = $1,
	type = $2,
	status = $3,
	url = $4,
	secret = $5,
	event_types = $6,
	created_at = $7,
	updated_at = $8
WHERE id = $9 AND status = $10`,
		endpoint.Name,
		string(endpoint.Type),
		string(endpoint.Status),
		endpoint.URL,
		endpoint.Secret,
		eventTypes,
		formatSQLTime(endpoint.CreatedAt),
		formatSQLTime(endpoint.UpdatedAt),
		endpoint.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := r.GetNotificationEndpoint(ctx, endpoint.ID); errors.Is(err, domain.ErrNotificationEndpointNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateAPIKey(ctx context.Context, key domain.APIKey) error {
	scopes, err := marshalAPIKeyScopes(key.Scopes)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO api_keys (
	id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)`,
		key.ID,
		key.Name,
		key.TokenHash,
		string(key.Status),
		key.Actor,
		scopes,
		formatNullableSQLTime(key.ExpiresAt),
		formatNullableSQLTime(key.LastUsedAt),
		formatSQLTime(key.CreatedAt),
		formatSQLTime(key.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	key, err := scanAPIKey(r.exec.QueryRowContext(ctx, `
SELECT id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.APIKey{}, domain.ErrAPIKeyNotFound
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (r sqlRepository) GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error) {
	key, err := scanAPIKey(r.exec.QueryRowContext(ctx, `
SELECT id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE token_hash = $1`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.APIKey{}, domain.ErrAPIKeyNotFound
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (r sqlRepository) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
FROM api_keys
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]domain.APIKey, 0)
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func (r sqlRepository) UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	scopes, err := marshalAPIKeyScopes(key.Scopes)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE api_keys
SET name = $1, token_hash = $2, status = $3, actor = $4, scopes = $5, expires_at = $6, last_used_at = $7, updated_at = $8
WHERE id = $9 AND status = $10`,
		key.Name,
		key.TokenHash,
		string(key.Status),
		key.Actor,
		scopes,
		formatNullableSQLTime(key.ExpiresAt),
		formatNullableSQLTime(key.LastUsedAt),
		formatSQLTime(key.UpdatedAt),
		key.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		if _, err := r.GetAPIKey(ctx, key.ID); errors.Is(err, domain.ErrAPIKeyNotFound) {
			return domain.ErrAPIKeyNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func scanIdentity(scanner sqlScanner) (domain.Identity, error) {
	var identity domain.Identity
	var identityType string
	var status string
	var allowedDNSNames string
	var allowedIPAddresses string
	var lastSeenAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&identity.ID,
		&identityType,
		&identity.Name,
		&identity.ExternalID,
		&identity.Owner,
		&identity.Team,
		&identity.Service,
		&identity.Environment,
		&identity.DeploymentTarget,
		&lastSeenAt,
		&identity.MetadataJSON,
		&allowedDNSNames,
		&allowedIPAddresses,
		&status,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Identity{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedLastSeenAt, err := parseSQLTime(lastSeenAt)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedAllowedDNSNames, err := unmarshalStringSlice(allowedDNSNames)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedAllowedIPAddresses, err := unmarshalStringSlice(allowedIPAddresses)
	if err != nil {
		return domain.Identity{}, err
	}

	identity.Type = domain.IdentityType(identityType)
	identity.LastSeenAt = parsedLastSeenAt
	identity.AllowedDNSNames = parsedAllowedDNSNames
	identity.AllowedIPAddresses = parsedAllowedIPAddresses
	identity.Status = domain.IdentityStatus(status)
	identity.CreatedAt = parsedCreatedAt
	identity.UpdatedAt = parsedUpdatedAt
	return identity, nil
}

func scanAPIKey(scanner sqlScanner) (domain.APIKey, error) {
	var key domain.APIKey
	var status string
	var scopes string
	var expiresAt any
	var lastUsedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&key.ID,
		&key.Name,
		&key.TokenHash,
		&status,
		&key.Actor,
		&scopes,
		&expiresAt,
		&lastUsedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.APIKey{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedScopes, err := unmarshalAPIKeyScopes(scopes)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedExpiresAt, err := parseSQLTime(expiresAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedLastUsedAt, err := parseSQLTime(lastUsedAt)
	if err != nil {
		return domain.APIKey{}, err
	}

	key.Status = domain.APIKeyStatus(status)
	key.Scopes = parsedScopes
	key.ExpiresAt = parsedExpiresAt
	key.LastUsedAt = parsedLastUsedAt
	key.CreatedAt = parsedCreatedAt
	key.UpdatedAt = parsedUpdatedAt
	return key, nil
}

func scanIssuer(scanner sqlScanner) (domain.Issuer, error) {
	var issuer domain.Issuer
	var kind string
	var status string
	var distributionPoints string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&issuer.ID,
		&issuer.Name,
		&kind,
		&status,
		&issuer.ParentIssuerID,
		&issuer.CertificatePEM,
		&issuer.KeyRef,
		&issuer.AIAURL,
		&distributionPoints,
		&issuer.TrustAnchor,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Issuer{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Issuer{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Issuer{}, err
	}
	parsedDistributionPoints, err := unmarshalStringSlice(distributionPoints)
	if err != nil {
		return domain.Issuer{}, err
	}

	issuer.Kind = domain.IssuerKind(kind)
	issuer.Status = domain.IssuerStatus(status)
	issuer.CRLDistributionPoints = parsedDistributionPoints
	issuer.CreatedAt = parsedCreatedAt
	issuer.UpdatedAt = parsedUpdatedAt
	return issuer, nil
}

func scanOCSPResponder(scanner sqlScanner) (domain.OCSPResponder, error) {
	var responder domain.OCSPResponder
	var status string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&responder.ID,
		&responder.IssuerID,
		&responder.Name,
		&status,
		&responder.CertificatePEM,
		&responder.KeyRef,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.OCSPResponder{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.OCSPResponder{}, err
	}

	responder.Status = domain.OCSPResponderStatus(status)
	responder.CreatedAt = parsedCreatedAt
	responder.UpdatedAt = parsedUpdatedAt
	return responder, nil
}

func scanNotificationEndpoint(scanner sqlScanner) (domain.NotificationEndpoint, error) {
	var endpoint domain.NotificationEndpoint
	var endpointType string
	var status string
	var eventTypes string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&endpoint.ID,
		&endpoint.Name,
		&endpointType,
		&status,
		&endpoint.URL,
		&endpoint.Secret,
		&eventTypes,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.NotificationEndpoint{}, err
	}

	parsedEventTypes, err := unmarshalStringSlice(eventTypes)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}

	endpoint.Type = domain.NotificationEndpointType(endpointType)
	endpoint.Status = domain.NotificationEndpointStatus(status)
	endpoint.EventTypes = parsedEventTypes
	endpoint.CreatedAt = parsedCreatedAt
	endpoint.UpdatedAt = parsedUpdatedAt
	return endpoint, nil
}

func scanCertificateProfile(scanner sqlScanner) (domain.CertificateProfile, error) {
	var profile domain.CertificateProfile
	var allowedDNSPatterns string
	var allowedIPRanges string
	var allowedKeyAlgorithms string
	var allowedSignatureAlgorithms string
	var keyUsage string
	var extendedKeyUsage string
	var basicConstraints string
	var subjectKeyIdentifier bool
	var authorityKeyIdentifier bool
	var publicTLS bool
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&profile.ID,
		&profile.Name,
		&profile.Description,
		&profile.IssuerID,
		&profile.ValidityPeriodSeconds,
		&profile.SubjectTemplate,
		&allowedDNSPatterns,
		&allowedIPRanges,
		&allowedKeyAlgorithms,
		&profile.MinKeySizeBits,
		&allowedSignatureAlgorithms,
		&keyUsage,
		&extendedKeyUsage,
		&basicConstraints,
		&subjectKeyIdentifier,
		&authorityKeyIdentifier,
		&publicTLS,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.CertificateProfile{}, err
	}

	parsedAllowedDNSPatterns, err := unmarshalStringSlice(allowedDNSPatterns)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedAllowedIPRanges, err := unmarshalStringSlice(allowedIPRanges)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedAllowedKeyAlgorithms, err := unmarshalStringSlice(allowedKeyAlgorithms)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedAllowedSignatureAlgorithms, err := unmarshalStringSlice(allowedSignatureAlgorithms)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	if err := unmarshalJSON(keyUsage, &profile.KeyUsage); err != nil {
		return domain.CertificateProfile{}, err
	}
	if err := unmarshalJSON(extendedKeyUsage, &profile.ExtendedKeyUsage); err != nil {
		return domain.CertificateProfile{}, err
	}
	if err := unmarshalBasicConstraintsPolicy(basicConstraints, &profile.BasicConstraints); err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.CertificateProfile{}, err
	}

	profile.AllowedDNSPatterns = parsedAllowedDNSPatterns
	profile.AllowedIPRanges = parsedAllowedIPRanges
	profile.AllowedKeyAlgorithms = parsedAllowedKeyAlgorithms
	profile.AllowedSignatureAlgorithms = parsedAllowedSignatureAlgorithms
	profile.SubjectKeyIdentifier = subjectKeyIdentifier
	profile.AuthorityKeyIdentifier = authorityKeyIdentifier
	profile.PublicTLS = publicTLS
	profile.CreatedAt = parsedCreatedAt
	profile.UpdatedAt = parsedUpdatedAt
	return profile, nil
}

func scanEnrollment(scanner sqlScanner) (domain.Enrollment, error) {
	var enrollment domain.Enrollment
	var status string
	var requestedDNSNames string
	var requestedIPAddresses string
	var csrDNSNames string
	var csrIPAddresses string
	var requestedNotAfter any
	var approvedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&enrollment.ID,
		&enrollment.IdentityID,
		&enrollment.IssuerID,
		&enrollment.CertificateProfileID,
		&enrollment.SourceCertificateID,
		&enrollment.CSRPEM,
		&status,
		&enrollment.RequestedSubject,
		&requestedDNSNames,
		&requestedIPAddresses,
		&csrDNSNames,
		&csrIPAddresses,
		&requestedNotAfter,
		&enrollment.ApprovedBy,
		&approvedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Enrollment{}, err
	}

	dnsNames, err := unmarshalStringSlice(requestedDNSNames)
	if err != nil {
		return domain.Enrollment{}, err
	}
	ipAddresses, err := unmarshalStringSlice(requestedIPAddresses)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedCSRDNSNames, err := unmarshalStringSlice(csrDNSNames)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedCSRIPAddresses, err := unmarshalStringSlice(csrIPAddresses)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedRequestedNotAfter, err := parseSQLTime(requestedNotAfter)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedApprovedAt, err := parseSQLTime(approvedAt)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Enrollment{}, err
	}

	enrollment.Status = domain.EnrollmentStatus(status)
	enrollment.RequestedDNSNames = dnsNames
	enrollment.RequestedIPAddresses = ipAddresses
	enrollment.CSRDNSNames = parsedCSRDNSNames
	enrollment.CSRIPAddresses = parsedCSRIPAddresses
	enrollment.RequestedNotAfter = parsedRequestedNotAfter
	enrollment.ApprovedAt = parsedApprovedAt
	enrollment.CreatedAt = parsedCreatedAt
	enrollment.UpdatedAt = parsedUpdatedAt
	return enrollment, nil
}

func scanCertificate(scanner sqlScanner) (domain.Certificate, error) {
	var certificate domain.Certificate
	var status string
	var dnsNames string
	var ipAddresses string
	var notBefore any
	var notAfter any
	var renewalNotifiedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&certificate.ID,
		&certificate.IdentityID,
		&certificate.IssuerID,
		&certificate.EnrollmentID,
		&certificate.CertificateProfileID,
		&certificate.SerialNumber,
		&certificate.Subject,
		&dnsNames,
		&ipAddresses,
		&notBefore,
		&notAfter,
		&status,
		&certificate.CertificatePEM,
		&renewalNotifiedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Certificate{}, err
	}

	parsedDNSNames, err := unmarshalStringSlice(dnsNames)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedIPAddresses, err := unmarshalStringSlice(ipAddresses)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedNotBefore, err := parseSQLTime(notBefore)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedNotAfter, err := parseSQLTime(notAfter)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedRenewalNotifiedAt, err := parseSQLTime(renewalNotifiedAt)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Certificate{}, err
	}

	certificate.DNSNames = parsedDNSNames
	certificate.IPAddresses = parsedIPAddresses
	certificate.NotBefore = parsedNotBefore
	certificate.NotAfter = parsedNotAfter
	certificate.Status = domain.CertificateStatus(status)
	certificate.RenewalNotifiedAt = parsedRenewalNotifiedAt
	certificate.CreatedAt = parsedCreatedAt
	certificate.UpdatedAt = parsedUpdatedAt
	return certificate, nil
}

func scanCertificateInventoryRecord(scanner sqlScanner) (CertificateInventoryRecord, error) {
	var record CertificateInventoryRecord
	var certificateStatus string
	var dnsNames string
	var ipAddresses string
	var notBefore any
	var notAfter any
	var renewalNotifiedAt any
	var certificateCreatedAt any
	var certificateUpdatedAt any
	var identityType string
	var identityStatus string
	var lastSeenAt any
	var allowedDNSNames string
	var allowedIPAddresses string
	var identityCreatedAt any
	var identityUpdatedAt any
	var issuerKind string
	var issuerStatus string
	var distributionPoints string
	var issuerCreatedAt any
	var issuerUpdatedAt any

	if err := scanner.Scan(
		&record.Certificate.ID,
		&record.Certificate.IdentityID,
		&record.Certificate.IssuerID,
		&record.Certificate.EnrollmentID,
		&record.Certificate.CertificateProfileID,
		&record.Certificate.SerialNumber,
		&record.Certificate.Subject,
		&dnsNames,
		&ipAddresses,
		&notBefore,
		&notAfter,
		&certificateStatus,
		&record.Certificate.CertificatePEM,
		&renewalNotifiedAt,
		&certificateCreatedAt,
		&certificateUpdatedAt,
		&record.Identity.ID,
		&identityType,
		&record.Identity.Name,
		&record.Identity.ExternalID,
		&record.Identity.Owner,
		&record.Identity.Team,
		&record.Identity.Service,
		&record.Identity.Environment,
		&record.Identity.DeploymentTarget,
		&lastSeenAt,
		&record.Identity.MetadataJSON,
		&allowedDNSNames,
		&allowedIPAddresses,
		&identityStatus,
		&identityCreatedAt,
		&identityUpdatedAt,
		&record.Issuer.ID,
		&record.Issuer.Name,
		&issuerKind,
		&issuerStatus,
		&record.Issuer.ParentIssuerID,
		&record.Issuer.CertificatePEM,
		&record.Issuer.KeyRef,
		&record.Issuer.AIAURL,
		&distributionPoints,
		&record.Issuer.TrustAnchor,
		&issuerCreatedAt,
		&issuerUpdatedAt,
	); err != nil {
		return CertificateInventoryRecord{}, err
	}

	var err error
	record.Certificate.DNSNames, err = unmarshalStringSlice(dnsNames)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.IPAddresses, err = unmarshalStringSlice(ipAddresses)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.NotBefore, err = parseSQLTime(notBefore)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.NotAfter, err = parseSQLTime(notAfter)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.RenewalNotifiedAt, err = parseSQLTime(renewalNotifiedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.CreatedAt, err = parseSQLTime(certificateCreatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.UpdatedAt, err = parseSQLTime(certificateUpdatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.Status = domain.CertificateStatus(certificateStatus)

	record.Identity.Type = domain.IdentityType(identityType)
	record.Identity.LastSeenAt, err = parseSQLTime(lastSeenAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.AllowedDNSNames, err = unmarshalStringSlice(allowedDNSNames)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.AllowedIPAddresses, err = unmarshalStringSlice(allowedIPAddresses)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.Status = domain.IdentityStatus(identityStatus)
	record.Identity.CreatedAt, err = parseSQLTime(identityCreatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.UpdatedAt, err = parseSQLTime(identityUpdatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}

	record.Issuer.Kind = domain.IssuerKind(issuerKind)
	record.Issuer.Status = domain.IssuerStatus(issuerStatus)
	record.Issuer.CRLDistributionPoints, err = unmarshalStringSlice(distributionPoints)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Issuer.CreatedAt, err = parseSQLTime(issuerCreatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Issuer.UpdatedAt, err = parseSQLTime(issuerUpdatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	return record, nil
}

func scanIssuanceAttempt(scanner sqlScanner) (domain.IssuanceAttempt, error) {
	var attempt domain.IssuanceAttempt
	var status string
	var leaseExpiresAt any
	var notBefore any
	var notAfter any
	var signingStartedAt any
	var signedAt any
	var finalizedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&attempt.EnrollmentID,
		&status,
		&leaseExpiresAt,
		&attempt.CertificateID,
		&attempt.CertificatePEM,
		&attempt.SerialNumber,
		&attempt.Subject,
		&notBefore,
		&notAfter,
		&signingStartedAt,
		&signedAt,
		&finalizedAt,
		&attempt.LastError,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedLeaseExpiresAt, err := parseSQLTime(leaseExpiresAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedNotBefore, err := parseSQLTime(notBefore)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedNotAfter, err := parseSQLTime(notAfter)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedSigningStartedAt, err := parseSQLTime(signingStartedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedSignedAt, err := parseSQLTime(signedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedFinalizedAt, err := parseSQLTime(finalizedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}

	attempt.Status = domain.IssuanceAttemptStatus(status)
	attempt.LeaseExpiresAt = parsedLeaseExpiresAt
	attempt.NotBefore = parsedNotBefore
	attempt.NotAfter = parsedNotAfter
	attempt.SigningStartedAt = parsedSigningStartedAt
	attempt.SignedAt = parsedSignedAt
	attempt.FinalizedAt = parsedFinalizedAt
	attempt.CreatedAt = parsedCreatedAt
	attempt.UpdatedAt = parsedUpdatedAt
	return attempt, nil
}

func scanAuditEvent(scanner sqlScanner) (domain.AuditEvent, error) {
	var event domain.AuditEvent
	var createdAt any

	if err := scanner.Scan(
		&event.ID,
		&event.Actor,
		&event.Action,
		&event.ResourceType,
		&event.ResourceID,
		&event.MetadataJSON,
		&createdAt,
	); err != nil {
		return domain.AuditEvent{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	event.CreatedAt = parsedCreatedAt
	return event, nil
}

func scanOutboxMessage(scanner sqlScanner) (domain.OutboxMessage, error) {
	var message domain.OutboxMessage
	var status string
	var availableAt any
	var processingDeadlineAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&message.ID,
		&message.Type,
		&message.PayloadJSON,
		&status,
		&availableAt,
		&processingDeadlineAt,
		&message.AttemptCount,
		&message.MaxAttempts,
		&message.LastError,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.OutboxMessage{}, err
	}

	parsedAvailableAt, err := parseSQLTime(availableAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	parsedProcessingDeadlineAt, err := parseSQLTime(processingDeadlineAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}

	message.Status = domain.OutboxMessageStatus(status)
	message.AvailableAt = parsedAvailableAt
	message.ProcessingDeadlineAt = parsedProcessingDeadlineAt
	message.CreatedAt = parsedCreatedAt
	message.UpdatedAt = parsedUpdatedAt
	return message, nil
}

func scanJobAttempt(scanner sqlScanner) (domain.JobAttempt, error) {
	var attempt domain.JobAttempt
	var status string
	var startedAt any
	var finishedAt any
	var createdAt any

	if err := scanner.Scan(
		&attempt.ID,
		&attempt.OutboxMessageID,
		&status,
		&attempt.Error,
		&startedAt,
		&finishedAt,
		&createdAt,
	); err != nil {
		return domain.JobAttempt{}, err
	}

	parsedStartedAt, err := parseSQLTime(startedAt)
	if err != nil {
		return domain.JobAttempt{}, err
	}
	parsedFinishedAt, err := parseSQLTime(finishedAt)
	if err != nil {
		return domain.JobAttempt{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.JobAttempt{}, err
	}

	attempt.Status = domain.JobAttemptStatus(status)
	attempt.StartedAt = parsedStartedAt
	attempt.FinishedAt = parsedFinishedAt
	attempt.CreatedAt = parsedCreatedAt
	return attempt, nil
}

func scanWebhookDelivery(scanner sqlScanner) (domain.WebhookDelivery, error) {
	var delivery domain.WebhookDelivery
	var status string
	var lastAttemptedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&delivery.OutboxMessageID,
		&delivery.EndpointID,
		&status,
		&delivery.AttemptCount,
		&delivery.LastError,
		&lastAttemptedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.WebhookDelivery{}, err
	}

	parsedLastAttemptedAt, err := parseSQLTime(lastAttemptedAt)
	if err != nil {
		return domain.WebhookDelivery{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.WebhookDelivery{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.WebhookDelivery{}, err
	}

	delivery.Status = domain.JobAttemptStatus(status)
	delivery.LastAttemptedAt = parsedLastAttemptedAt
	delivery.CreatedAt = parsedCreatedAt
	delivery.UpdatedAt = parsedUpdatedAt
	return delivery, nil
}

func scanRevokedCertificateEntry(scanner sqlScanner) (domain.RevokedCertificateEntry, error) {
	var entry domain.RevokedCertificateEntry
	var reason string
	var revokedAt any
	if err := scanner.Scan(
		&entry.CertificateID,
		&entry.SerialNumber,
		&revokedAt,
		&reason,
	); err != nil {
		return domain.RevokedCertificateEntry{}, err
	}
	parsedRevokedAt, err := parseSQLTime(revokedAt)
	if err != nil {
		return domain.RevokedCertificateEntry{}, err
	}
	entry.RevokedAt = parsedRevokedAt
	entry.Reason = domain.RevocationReason(reason)
	return entry, nil
}

func scanCRLPublication(scanner sqlScanner) (domain.CRLPublication, error) {
	var publication domain.CRLPublication
	var status string
	var thisUpdate any
	var nextUpdate any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&publication.ID,
		&publication.IssuerID,
		&publication.DistributionPoint,
		&publication.CRLNumber,
		&thisUpdate,
		&nextUpdate,
		&status,
		&publication.CRLPEM,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.CRLPublication{}, err
	}
	parsedThisUpdate, err := parseSQLTime(thisUpdate)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	parsedNextUpdate, err := parseSQLTime(nextUpdate)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	publication.ThisUpdate = parsedThisUpdate
	publication.NextUpdate = parsedNextUpdate
	publication.Status = domain.CRLPublicationStatus(status)
	publication.CreatedAt = parsedCreatedAt
	publication.UpdatedAt = parsedUpdatedAt
	return publication, nil
}

func marshalStringSlice(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func marshalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func unmarshalJSON(data string, value any) error {
	if data == "" {
		return nil
	}
	return json.Unmarshal([]byte(data), value)
}

func unmarshalBasicConstraintsPolicy(data string, value *domain.BasicConstraintsPolicy) error {
	if data == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(data), value); err != nil {
		return err
	}
	if !value.CA && value.MaxPathLen != nil && *value.MaxPathLen == 0 {
		value.MaxPathLen = nil
	}
	return nil
}

func unmarshalStringSlice(data string) ([]string, error) {
	if data == "" {
		return []string{}, nil
	}

	var values []string
	if err := json.Unmarshal([]byte(data), &values); err != nil {
		return nil, err
	}
	if values == nil {
		return []string{}, nil
	}
	return values, nil
}

func marshalAPIKeyScopes(scopes []domain.APIKeyScope) (string, error) {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		values = append(values, string(scope))
	}
	return marshalStringSlice(values)
}

func unmarshalAPIKeyScopes(data string) ([]domain.APIKeyScope, error) {
	values, err := unmarshalStringSlice(data)
	if err != nil {
		return nil, err
	}
	scopes := make([]domain.APIKeyScope, 0, len(values))
	for _, value := range values {
		scopes = append(scopes, domain.APIKeyScope(value))
	}
	return scopes, nil
}

const sqlTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatSQLTime(value time.Time) string {
	return value.UTC().Format(sqlTimeLayout)
}

func formatNullableSQLTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return formatSQLTime(value)
}

func parseSQLTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		if v.IsZero() {
			return time.Time{}, nil
		}
		return v, nil
	case string:
		return parseSQLTimeString(v)
	case []byte:
		return parseSQLTimeString(string(v))
	default:
		return time.Time{}, fmt.Errorf("unsupported SQL time value %T", value)
	}
}

func parseSQLTimeString(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	parsed, err := time.Parse(sqlTimeLayout, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return time.Time{}, err
		}
	}
	if parsed.IsZero() {
		return time.Time{}, nil
	}
	return parsed, nil
}

func requireRowsAffected(result sql.Result, missingErr error) error {
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return missingErr
	}
	return nil
}

func affectedRows(result sql.Result) (int64, error) {
	return result.RowsAffected()
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint failed") ||
		strings.Contains(message, "duplicate key value violates unique constraint")
}
