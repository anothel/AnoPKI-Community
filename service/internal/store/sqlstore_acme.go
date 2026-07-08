// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/anothel/anopki/service/internal/domain"
)

func (s *SQLStore) CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error {
	return s.repository().CreateACMEAccount(ctx, account)
}

func (s *SQLStore) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	return s.repository().GetACMEAccount(ctx, id)
}

func (s *SQLStore) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	return s.repository().ListACMEAccounts(ctx)
}

func (s *SQLStore) UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	return s.repository().UpdateACMEAccountIfStatus(ctx, account, currentStatus)
}

func (s *SQLStore) CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error {
	return s.repository().CreateACMEOrder(ctx, order)
}

func (s *SQLStore) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	return s.repository().GetACMEOrder(ctx, id)
}

func (s *SQLStore) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	return s.repository().ListACMEOrdersByAccount(ctx, accountID)
}

func (s *SQLStore) UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	return s.repository().UpdateACMEOrderIfStatus(ctx, order, currentStatus)
}

func (s *SQLStore) CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error {
	return s.repository().CreateACMEAuthorization(ctx, authorization)
}

func (s *SQLStore) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	return s.repository().GetACMEAuthorization(ctx, id)
}

func (s *SQLStore) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	return s.repository().ListACMEAuthorizationsByOrder(ctx, orderID)
}

func (s *SQLStore) UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	return s.repository().UpdateACMEAuthorizationIfStatus(ctx, authorization, currentStatus)
}

func (s *SQLStore) CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error {
	return s.repository().CreateACMEChallenge(ctx, challenge)
}

func (s *SQLStore) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	return s.repository().GetACMEChallenge(ctx, id)
}

func (s *SQLStore) ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	return s.repository().ListACMEChallengesByAuthorization(ctx, authorizationID)
}

func (s *SQLStore) UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	return s.repository().UpdateACMEChallengeIfStatus(ctx, challenge, currentStatus)
}

func (r sqlRepository) CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error {
	contacts, err := marshalStringSlice(account.Contacts)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO acme_accounts (
	id, contacts, status, terms_of_service_agreed, key_thumbprint, key_jwk_json, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		account.ID,
		contacts,
		string(account.Status),
		account.TermsOfServiceAgreed,
		account.KeyThumbprint,
		account.KeyJWKJSON,
		formatSQLTime(account.CreatedAt),
		formatSQLTime(account.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	account, err := scanACMEAccount(r.exec.QueryRowContext(ctx, `
SELECT id, contacts, status, terms_of_service_agreed, key_thumbprint, key_jwk_json, created_at, updated_at
FROM acme_accounts
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEAccount{}, domain.ErrACMEAccountNotFound
	}
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	return account, nil
}

func (r sqlRepository) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, contacts, status, terms_of_service_agreed, key_thumbprint, key_jwk_json, created_at, updated_at
FROM acme_accounts
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := make([]domain.ACMEAccount, 0)
	for rows.Next() {
		account, err := scanACMEAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (r sqlRepository) UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	contacts, err := marshalStringSlice(account.Contacts)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_accounts
SET contacts = $1, status = $2, terms_of_service_agreed = $3, key_thumbprint = $4, key_jwk_json = $5, updated_at = $6
WHERE id = $7 AND status = $8`,
		contacts,
		string(account.Status),
		account.TermsOfServiceAgreed,
		account.KeyThumbprint,
		account.KeyJWKJSON,
		formatSQLTime(account.UpdatedAt),
		account.ID,
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
		if _, err := r.GetACMEAccount(ctx, account.ID); errors.Is(err, domain.ErrACMEAccountNotFound) {
			return domain.ErrACMEAccountNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error {
	dnsNames, err := marshalStringSlice(order.RequestedDNSNames)
	if err != nil {
		return err
	}
	ipAddresses, err := marshalStringSlice(order.RequestedIPAddresses)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO acme_orders (
	id, account_id, identity_id, issuer_id, certificate_profile_id, status, csr_pem,
	requested_subject, requested_dns_names, requested_ip_addresses, requested_not_after,
	enrollment_id, certificate_id, expires_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		order.ID,
		order.AccountID,
		order.IdentityID,
		order.IssuerID,
		order.CertificateProfileID,
		string(order.Status),
		order.CSRPEM,
		order.RequestedSubject,
		dnsNames,
		ipAddresses,
		formatSQLTime(order.RequestedNotAfter),
		order.EnrollmentID,
		order.CertificateID,
		formatSQLTime(order.ExpiresAt),
		formatSQLTime(order.CreatedAt),
		formatSQLTime(order.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	order, err := scanACMEOrder(r.exec.QueryRowContext(ctx, `
SELECT id, account_id, identity_id, issuer_id, certificate_profile_id, status, csr_pem,
	requested_subject, requested_dns_names, requested_ip_addresses, requested_not_after,
	enrollment_id, certificate_id, expires_at, created_at, updated_at
FROM acme_orders
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEOrder{}, domain.ErrACMEOrderNotFound
	}
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	return order, nil
}

func (r sqlRepository) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, account_id, identity_id, issuer_id, certificate_profile_id, status, csr_pem,
	requested_subject, requested_dns_names, requested_ip_addresses, requested_not_after,
	enrollment_id, certificate_id, expires_at, created_at, updated_at
FROM acme_orders
WHERE account_id = $1
ORDER BY created_at, id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	orders := make([]domain.ACMEOrder, 0)
	for rows.Next() {
		order, err := scanACMEOrder(rows)
		if err != nil {
			return nil, err
		}
		orders = append(orders, order)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return orders, nil
}

func (r sqlRepository) UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	dnsNames, err := marshalStringSlice(order.RequestedDNSNames)
	if err != nil {
		return err
	}
	ipAddresses, err := marshalStringSlice(order.RequestedIPAddresses)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_orders
SET account_id = $1, identity_id = $2, issuer_id = $3, certificate_profile_id = $4,
	status = $5, csr_pem = $6, requested_subject = $7, requested_dns_names = $8,
	requested_ip_addresses = $9, requested_not_after = $10, enrollment_id = $11,
	certificate_id = $12, expires_at = $13, created_at = $14, updated_at = $15
WHERE id = $16 AND status = $17`,
		order.AccountID,
		order.IdentityID,
		order.IssuerID,
		order.CertificateProfileID,
		string(order.Status),
		order.CSRPEM,
		order.RequestedSubject,
		dnsNames,
		ipAddresses,
		formatSQLTime(order.RequestedNotAfter),
		order.EnrollmentID,
		order.CertificateID,
		formatSQLTime(order.ExpiresAt),
		formatSQLTime(order.CreatedAt),
		formatSQLTime(order.UpdatedAt),
		order.ID,
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
		if _, err := r.GetACMEOrder(ctx, order.ID); errors.Is(err, domain.ErrACMEOrderNotFound) {
			return domain.ErrACMEOrderNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO acme_authorizations (
	id, order_id, identifier_type, identifier_value, status, expires_at, validation_reuse_expires_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9
)`,
		authorization.ID,
		authorization.OrderID,
		authorization.IdentifierType,
		authorization.IdentifierValue,
		string(authorization.Status),
		formatSQLTime(authorization.ExpiresAt),
		formatNullableSQLTime(authorization.ValidationReuseExpiresAt),
		formatSQLTime(authorization.CreatedAt),
		formatSQLTime(authorization.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	authorization, err := scanACMEAuthorization(r.exec.QueryRowContext(ctx, `
SELECT id, order_id, identifier_type, identifier_value, status, expires_at, validation_reuse_expires_at, created_at, updated_at
FROM acme_authorizations
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEAuthorization{}, domain.ErrACMEAuthorizationNotFound
	}
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	return authorization, nil
}

func (r sqlRepository) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, order_id, identifier_type, identifier_value, status, expires_at, validation_reuse_expires_at, created_at, updated_at
FROM acme_authorizations
WHERE order_id = $1
ORDER BY created_at, id`, orderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	authorizations := make([]domain.ACMEAuthorization, 0)
	for rows.Next() {
		authorization, err := scanACMEAuthorization(rows)
		if err != nil {
			return nil, err
		}
		authorizations = append(authorizations, authorization)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return authorizations, nil
}

func (r sqlRepository) UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_authorizations
SET order_id = $1, identifier_type = $2, identifier_value = $3, status = $4, expires_at = $5, validation_reuse_expires_at = $6, created_at = $7, updated_at = $8
WHERE id = $9 AND status = $10`,
		authorization.OrderID,
		authorization.IdentifierType,
		authorization.IdentifierValue,
		string(authorization.Status),
		formatSQLTime(authorization.ExpiresAt),
		formatNullableSQLTime(authorization.ValidationReuseExpiresAt),
		formatSQLTime(authorization.CreatedAt),
		formatSQLTime(authorization.UpdatedAt),
		authorization.ID,
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
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO acme_challenges (
	id, authorization_id, type, token, status, validated_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		challenge.ID,
		challenge.AuthorizationID,
		string(challenge.Type),
		challenge.Token,
		string(challenge.Status),
		formatNullableSQLTime(challenge.ValidatedAt),
		formatSQLTime(challenge.CreatedAt),
		formatSQLTime(challenge.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	challenge, err := scanACMEChallenge(r.exec.QueryRowContext(ctx, `
SELECT id, authorization_id, type, token, status, validated_at, created_at, updated_at
FROM acme_challenges
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEChallenge{}, domain.ErrACMEChallengeNotFound
	}
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	return challenge, nil
}

func (r sqlRepository) ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, authorization_id, type, token, status, validated_at, created_at, updated_at
FROM acme_challenges
WHERE authorization_id = $1
ORDER BY created_at, id`, authorizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	challenges := make([]domain.ACMEChallenge, 0)
	for rows.Next() {
		challenge, err := scanACMEChallenge(rows)
		if err != nil {
			return nil, err
		}
		challenges = append(challenges, challenge)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return challenges, nil
}

func (r sqlRepository) UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_challenges
SET authorization_id = $1, type = $2, token = $3, status = $4, validated_at = $5, created_at = $6, updated_at = $7
WHERE id = $8 AND status = $9`,
		challenge.AuthorizationID,
		string(challenge.Type),
		challenge.Token,
		string(challenge.Status),
		formatNullableSQLTime(challenge.ValidatedAt),
		formatSQLTime(challenge.CreatedAt),
		formatSQLTime(challenge.UpdatedAt),
		challenge.ID,
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
		if _, err := r.GetACMEChallenge(ctx, challenge.ID); errors.Is(err, domain.ErrACMEChallengeNotFound) {
			return domain.ErrACMEChallengeNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func scanACMEAccount(scanner sqlScanner) (domain.ACMEAccount, error) {
	var account domain.ACMEAccount
	var status string
	var contacts string
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&account.ID,
		&contacts,
		&status,
		&account.TermsOfServiceAgreed,
		&account.KeyThumbprint,
		&account.KeyJWKJSON,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEAccount{}, err
	}
	parsedContacts, err := unmarshalStringSlice(contacts)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	account.Contacts = parsedContacts
	account.Status = domain.ACMEAccountStatus(status)
	account.CreatedAt = parsedCreatedAt
	account.UpdatedAt = parsedUpdatedAt
	return account, nil
}

func scanACMEOrder(scanner sqlScanner) (domain.ACMEOrder, error) {
	var order domain.ACMEOrder
	var status string
	var requestedDNSNames string
	var requestedIPAddresses string
	var requestedNotAfter any
	var expiresAt any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&order.ID,
		&order.AccountID,
		&order.IdentityID,
		&order.IssuerID,
		&order.CertificateProfileID,
		&status,
		&order.CSRPEM,
		&order.RequestedSubject,
		&requestedDNSNames,
		&requestedIPAddresses,
		&requestedNotAfter,
		&order.EnrollmentID,
		&order.CertificateID,
		&expiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEOrder{}, err
	}
	dnsNames, err := unmarshalStringSlice(requestedDNSNames)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	ipAddresses, err := unmarshalStringSlice(requestedIPAddresses)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedRequestedNotAfter, err := parseSQLTime(requestedNotAfter)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedExpiresAt, err := parseSQLTime(expiresAt)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	order.Status = domain.ACMEOrderStatus(status)
	order.RequestedDNSNames = dnsNames
	order.RequestedIPAddresses = ipAddresses
	order.RequestedNotAfter = parsedRequestedNotAfter
	order.ExpiresAt = parsedExpiresAt
	order.CreatedAt = parsedCreatedAt
	order.UpdatedAt = parsedUpdatedAt
	return order, nil
}

func scanACMEAuthorization(scanner sqlScanner) (domain.ACMEAuthorization, error) {
	var authorization domain.ACMEAuthorization
	var status string
	var expiresAt any
	var validationReuseExpiresAt any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&authorization.ID,
		&authorization.OrderID,
		&authorization.IdentifierType,
		&authorization.IdentifierValue,
		&status,
		&expiresAt,
		&validationReuseExpiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedExpiresAt, err := parseSQLTime(expiresAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedValidationReuseExpiresAt, err := parseSQLTime(validationReuseExpiresAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	authorization.Status = domain.ACMEAuthorizationStatus(status)
	authorization.ExpiresAt = parsedExpiresAt
	authorization.ValidationReuseExpiresAt = parsedValidationReuseExpiresAt
	authorization.CreatedAt = parsedCreatedAt
	authorization.UpdatedAt = parsedUpdatedAt
	return authorization, nil
}

func scanACMEChallenge(scanner sqlScanner) (domain.ACMEChallenge, error) {
	var challenge domain.ACMEChallenge
	var challengeType string
	var status string
	var validatedAt any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&challenge.ID,
		&challenge.AuthorizationID,
		&challengeType,
		&challenge.Token,
		&status,
		&validatedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEChallenge{}, err
	}
	parsedValidatedAt, err := parseSQLTime(validatedAt)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	challenge.Type = domain.ACMEChallengeType(challengeType)
	challenge.Status = domain.ACMEChallengeStatus(status)
	challenge.ValidatedAt = parsedValidatedAt
	challenge.CreatedAt = parsedCreatedAt
	challenge.UpdatedAt = parsedUpdatedAt
	return challenge, nil
}
