// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func (s *SQLStore) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	return s.repository().CreateCertificateProfile(ctx, profile)
}

func (s *SQLStore) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	return s.repository().GetCertificateProfile(ctx, id)
}

func (s *SQLStore) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	return s.repository().ListCertificateProfiles(ctx)
}

func (s *SQLStore) UpdateCertificateProfileIssuerIfCurrent(ctx context.Context, profile domain.CertificateProfile, currentIssuerID string, currentUpdatedAt time.Time) error {
	return s.repository().UpdateCertificateProfileIssuerIfCurrent(ctx, profile, currentIssuerID, currentUpdatedAt)
}

func (s *SQLStore) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	return s.repository().CreateEnrollment(ctx, enrollment)
}

func (s *SQLStore) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	return s.repository().GetEnrollment(ctx, id)
}

func (s *SQLStore) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	return s.repository().ListEnrollments(ctx)
}

func (s *SQLStore) ListEnrollmentsQuery(ctx context.Context, query EnrollmentQuery) ([]domain.Enrollment, error) {
	return s.repository().ListEnrollmentsQuery(ctx, query)
}

func (s *SQLStore) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	return s.repository().UpdateEnrollment(ctx, enrollment)
}

func (s *SQLStore) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	return s.repository().UpdateEnrollmentIfStatus(ctx, enrollment, currentStatus)
}

func (s *SQLStore) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	return s.repository().CreateCertificate(ctx, certificate)
}

func (s *SQLStore) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	return s.repository().GetCertificate(ctx, id)
}

func (s *SQLStore) GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error) {
	return s.repository().GetCertificateByEnrollmentID(ctx, enrollmentID)
}

func (s *SQLStore) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	return s.repository().ListCertificates(ctx)
}

func (s *SQLStore) ListCertificatesQuery(ctx context.Context, query CertificateQuery) ([]domain.Certificate, error) {
	return s.repository().ListCertificatesQuery(ctx, query)
}

func (s *SQLStore) ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error) {
	return s.repository().ListCertificateInventory(ctx, filter)
}

func (s *SQLStore) ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error) {
	return s.repository().ListCertificatesExpiringWithin(ctx, now, cutoff, limit, offset)
}

func (s *SQLStore) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	return s.repository().ListCertificatesForExpirationScan(ctx, now, warningBefore, limit)
}

func (s *SQLStore) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	return s.repository().UpdateCertificate(ctx, certificate)
}

func (s *SQLStore) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	return s.repository().UpdateCertificateIfStatus(ctx, certificate, currentStatus)
}

func (s *SQLStore) CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error {
	return s.repository().CreateIssuanceAttempt(ctx, attempt)
}

func (s *SQLStore) GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error) {
	return s.repository().GetIssuanceAttempt(ctx, enrollmentID)
}

func (s *SQLStore) UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	return s.repository().UpdateIssuanceAttemptIfCurrent(ctx, attempt, current)
}

func (s *SQLStore) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	return s.repository().CreateRevocation(ctx, revocation)
}

func (s *SQLStore) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	return s.repository().ListRevocationsByIssuer(ctx, issuerID)
}

func (s *SQLStore) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	return s.repository().CreateCRLPublication(ctx, publication)
}

func (s *SQLStore) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	return s.repository().GetCRLPublication(ctx, id)
}

func (s *SQLStore) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	return s.repository().GetLatestCRLPublicationByIssuer(ctx, issuerID)
}

func (s *SQLStore) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	return s.repository().ListCRLPublicationsByIssuer(ctx, issuerID)
}

func (s *SQLStore) CreateCRLGenerationClaim(ctx context.Context, claim domain.CRLGenerationClaim) error {
	return s.repository().CreateCRLGenerationClaim(ctx, claim)
}

func (s *SQLStore) GetCRLGenerationClaim(ctx context.Context, issuerID string, distributionPoint string) (domain.CRLGenerationClaim, error) {
	return s.repository().GetCRLGenerationClaim(ctx, issuerID, distributionPoint)
}

func (s *SQLStore) UpdateCRLGenerationClaimIfCurrent(ctx context.Context, claim domain.CRLGenerationClaim, current domain.CRLGenerationClaim) error {
	return s.repository().UpdateCRLGenerationClaimIfCurrent(ctx, claim, current)
}

func (s *SQLStore) DeleteCRLGenerationClaimIfCurrent(ctx context.Context, current domain.CRLGenerationClaim) error {
	return s.repository().DeleteCRLGenerationClaimIfCurrent(ctx, current)
}

func (r sqlRepository) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	allowedDNSPatterns, err := marshalStringSlice(profile.AllowedDNSPatterns)
	if err != nil {
		return err
	}
	allowedIPRanges, err := marshalStringSlice(profile.AllowedIPRanges)
	if err != nil {
		return err
	}
	allowedKeyAlgorithms, err := marshalStringSlice(profile.AllowedKeyAlgorithms)
	if err != nil {
		return err
	}
	allowedSignatureAlgorithms, err := marshalStringSlice(profile.AllowedSignatureAlgorithms)
	if err != nil {
		return err
	}
	keyUsage, err := marshalJSON(profile.KeyUsage)
	if err != nil {
		return err
	}
	extendedKeyUsage, err := marshalJSON(profile.ExtendedKeyUsage)
	if err != nil {
		return err
	}
	basicConstraints, err := marshalJSON(profile.BasicConstraints)
	if err != nil {
		return err
	}

	_, err = r.exec.ExecContext(ctx, `
INSERT INTO certificate_profiles (
	id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
	allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
	subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
)`,
		profile.ID,
		profile.Name,
		profile.Description,
		profile.IssuerID,
		profile.ValidityPeriodSeconds,
		profile.SubjectTemplate,
		allowedDNSPatterns,
		allowedIPRanges,
		allowedKeyAlgorithms,
		profile.MinKeySizeBits,
		allowedSignatureAlgorithms,
		keyUsage,
		extendedKeyUsage,
		basicConstraints,
		profile.SubjectKeyIdentifier,
		profile.AuthorityKeyIdentifier,
		profile.PublicTLS,
		formatSQLTime(profile.CreatedAt),
		formatSQLTime(profile.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	profile, err := scanCertificateProfile(r.exec.QueryRowContext(ctx, `
SELECT id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
	allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
	subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
FROM certificate_profiles
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CertificateProfile{}, domain.ErrCertificateProfileNotFound
	}
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	return profile, nil
}

func (r sqlRepository) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
	allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
	subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
FROM certificate_profiles
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	profiles := make([]domain.CertificateProfile, 0)
	for rows.Next() {
		profile, err := scanCertificateProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return profiles, nil
}

func (r sqlRepository) UpdateCertificateProfileIssuerIfCurrent(ctx context.Context, profile domain.CertificateProfile, currentIssuerID string, currentUpdatedAt time.Time) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE certificate_profiles
SET issuer_id = $1, updated_at = $2
WHERE id = $3 AND issuer_id = $4 AND updated_at = $5`,
		profile.IssuerID,
		formatSQLTime(profile.UpdatedAt),
		profile.ID,
		currentIssuerID,
		formatSQLTime(currentUpdatedAt),
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		if _, getErr := r.GetCertificateProfile(ctx, profile.ID); getErr != nil {
			return getErr
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	requestedDNSNames, err := marshalStringSlice(enrollment.RequestedDNSNames)
	if err != nil {
		return err
	}
	requestedIPAddresses, err := marshalStringSlice(enrollment.RequestedIPAddresses)
	if err != nil {
		return err
	}
	csrDNSNames, err := marshalStringSlice(enrollment.CSRDNSNames)
	if err != nil {
		return err
	}
	csrIPAddresses, err := marshalStringSlice(enrollment.CSRIPAddresses)
	if err != nil {
		return err
	}

	_, err = r.exec.ExecContext(ctx, `
INSERT INTO enrollments (
	id, identity_id, issuer_id, certificate_profile_id, source_certificate_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
)`,
		enrollment.ID,
		enrollment.IdentityID,
		enrollment.IssuerID,
		enrollment.CertificateProfileID,
		enrollment.SourceCertificateID,
		enrollment.CSRPEM,
		string(enrollment.Status),
		enrollment.RequestedSubject,
		requestedDNSNames,
		requestedIPAddresses,
		csrDNSNames,
		csrIPAddresses,
		formatSQLTime(enrollment.RequestedNotAfter),
		enrollment.ApprovedBy,
		formatNullableSQLTime(enrollment.ApprovedAt),
		formatSQLTime(enrollment.CreatedAt),
		formatSQLTime(enrollment.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	enrollment, err := scanEnrollment(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, certificate_profile_id, source_certificate_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
FROM enrollments
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Enrollment{}, domain.ErrEnrollmentNotFound
	}
	if err != nil {
		return domain.Enrollment{}, err
	}
	return enrollment, nil
}

func (r sqlRepository) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, identity_id, issuer_id, certificate_profile_id, source_certificate_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
FROM enrollments
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	enrollments := make([]domain.Enrollment, 0)
	for rows.Next() {
		enrollment, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		enrollments = append(enrollments, enrollment)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return enrollments, nil
}

func (r sqlRepository) ListEnrollmentsQuery(ctx context.Context, query EnrollmentQuery) ([]domain.Enrollment, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, identity_id, issuer_id, certificate_profile_id, source_certificate_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
FROM enrollments`)
	args := make([]any, 0)
	conditions := make([]string, 0)
	addSQLStringCondition(&args, &conditions, "identity_id", query.IdentityID)
	addSQLStringCondition(&args, &conditions, "issuer_id", query.IssuerID)
	addSQLStringCondition(&args, &conditions, "certificate_profile_id", query.ProfileID)
	if query.Status != "" {
		addSQLStringCondition(&args, &conditions, "status", string(query.Status))
	}
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "created_at", "id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	enrollments := make([]domain.Enrollment, 0)
	for rows.Next() {
		enrollment, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		enrollments = append(enrollments, enrollment)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return enrollments, nil
}

func (r sqlRepository) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	result, err := r.updateEnrollment(ctx, enrollment, "", false)
	if err != nil {
		return err
	}
	return requireRowsAffected(result, domain.ErrEnrollmentNotFound)
}

func (r sqlRepository) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	result, err := r.updateEnrollment(ctx, enrollment, currentStatus, true)
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
	if _, err := r.GetEnrollment(ctx, enrollment.ID); errors.Is(err, domain.ErrEnrollmentNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) updateEnrollment(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus, requireStatus bool) (sql.Result, error) {
	requestedDNSNames, err := marshalStringSlice(enrollment.RequestedDNSNames)
	if err != nil {
		return nil, err
	}
	requestedIPAddresses, err := marshalStringSlice(enrollment.RequestedIPAddresses)
	if err != nil {
		return nil, err
	}
	csrDNSNames, err := marshalStringSlice(enrollment.CSRDNSNames)
	if err != nil {
		return nil, err
	}
	csrIPAddresses, err := marshalStringSlice(enrollment.CSRIPAddresses)
	if err != nil {
		return nil, err
	}

	query := `
UPDATE enrollments
SET identity_id = $1,
	issuer_id = $2,
	certificate_profile_id = $3,
	source_certificate_id = $4,
	csr_pem = $5,
	status = $6,
	requested_subject = $7,
	requested_dns_names = $8,
	requested_ip_addresses = $9,
	csr_dns_names = $10,
	csr_ip_addresses = $11,
	requested_not_after = $12,
	approved_by = $13,
	approved_at = $14,
	created_at = $15,
	updated_at = $16
WHERE id = $17`
	args := []any{
		enrollment.IdentityID,
		enrollment.IssuerID,
		enrollment.CertificateProfileID,
		enrollment.SourceCertificateID,
		enrollment.CSRPEM,
		string(enrollment.Status),
		enrollment.RequestedSubject,
		requestedDNSNames,
		requestedIPAddresses,
		csrDNSNames,
		csrIPAddresses,
		formatSQLTime(enrollment.RequestedNotAfter),
		enrollment.ApprovedBy,
		formatNullableSQLTime(enrollment.ApprovedAt),
		formatSQLTime(enrollment.CreatedAt),
		formatSQLTime(enrollment.UpdatedAt),
		enrollment.ID,
	}
	if requireStatus {
		query += `
AND status = $18`
		args = append(args, string(currentStatus))
	}
	return r.exec.ExecContext(ctx, query, args...)
}

func (r sqlRepository) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	dnsNames, err := marshalStringSlice(certificate.DNSNames)
	if err != nil {
		return err
	}
	ipAddresses, err := marshalStringSlice(certificate.IPAddresses)
	if err != nil {
		return err
	}

	_, err = r.exec.ExecContext(ctx, `
INSERT INTO certificates (
	id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		certificate.ID,
		certificate.IdentityID,
		certificate.IssuerID,
		certificate.EnrollmentID,
		certificate.CertificateProfileID,
		certificate.SerialNumber,
		certificate.Subject,
		dnsNames,
		ipAddresses,
		formatSQLTime(certificate.NotBefore),
		formatSQLTime(certificate.NotAfter),
		string(certificate.Status),
		certificate.CertificatePEM,
		formatNullableSQLTime(certificate.RenewalNotifiedAt),
		formatSQLTime(certificate.CreatedAt),
		formatSQLTime(certificate.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	certificate, err := scanCertificate(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	if err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (r sqlRepository) GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error) {
	certificate, err := scanCertificate(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE enrollment_id = $1`, enrollmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	if err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (r sqlRepository) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certificates := make([]domain.Certificate, 0)
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (r sqlRepository) ListCertificatesQuery(ctx context.Context, query CertificateQuery) ([]domain.Certificate, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT c.id, c.identity_id, c.issuer_id, c.enrollment_id, c.certificate_profile_id, c.serial_number, c.subject,
	c.dns_names, c.ip_addresses, c.not_before, c.not_after, c.status, c.certificate_pem,
	c.renewal_notified_at, c.created_at, c.updated_at
FROM certificates c`)
	if query.Owner != "" || query.Team != "" || query.Service != "" || query.Environment != "" {
		sqlQuery.WriteString(`
JOIN identities i ON i.id = c.identity_id`)
	}
	args := make([]any, 0)
	conditions := make([]string, 0)
	addSQLStringCondition(&args, &conditions, "i.owner", query.Owner)
	addSQLStringCondition(&args, &conditions, "i.team", query.Team)
	addSQLStringCondition(&args, &conditions, "i.service", query.Service)
	addSQLStringCondition(&args, &conditions, "i.environment", query.Environment)
	addSQLStringCondition(&args, &conditions, "c.issuer_id", query.IssuerID)
	addSQLStringCondition(&args, &conditions, "c.certificate_profile_id", query.ProfileID)
	addSQLStringCondition(&args, &conditions, "c.status", query.RevocationState)
	if query.SAN != "" {
		pattern, err := sqlJSONStringElementPattern(query.SAN)
		if err != nil {
			return nil, err
		}
		args = append(args, pattern, pattern)
		conditions = append(conditions, fmt.Sprintf("(c.dns_names LIKE $%d OR c.ip_addresses LIKE $%d)", len(args)-1, len(args)))
	}
	if query.RenewalState == "notified" {
		conditions = append(conditions, "c.renewal_notified_at IS NOT NULL")
	} else if query.RenewalState == "unnotified" {
		conditions = append(conditions, "c.renewal_notified_at IS NULL")
	}
	if !query.ExpiresAfter.IsZero() {
		args = append(args, formatSQLTime(query.ExpiresAfter))
		conditions = append(conditions, fmt.Sprintf("c.not_after > $%d", len(args)))
	}
	if !query.ExpiresBefore.IsZero() {
		args = append(args, formatSQLTime(query.ExpiresBefore))
		conditions = append(conditions, fmt.Sprintf("c.not_after <= $%d", len(args)))
	}
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "c.created_at", "c.id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certificates := make([]domain.Certificate, 0)
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (r sqlRepository) ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error) {
	query := `
SELECT
	c.id, c.identity_id, c.issuer_id, c.enrollment_id, c.certificate_profile_id, c.serial_number, c.subject,
	c.dns_names, c.ip_addresses, c.not_before, c.not_after, c.status, c.certificate_pem,
	c.renewal_notified_at, c.created_at, c.updated_at,
	i.id, i.type, i.name, i.external_id, i.owner, i.team, i.service, i.environment, i.deployment_target, i.last_seen_at,
	i.metadata_json, i.allowed_dns_names, i.allowed_ip_addresses, i.status, i.created_at, i.updated_at,
	iss.id, iss.name, iss.kind, iss.status, iss.parent_issuer_id, iss.certificate_pem, iss.key_ref, iss.aia_url, iss.crl_distribution_points, iss.trust_anchor, iss.created_at, iss.updated_at
FROM certificates c
JOIN identities i ON i.id = c.identity_id
JOIN issuers iss ON iss.id = c.issuer_id`
	args := make([]any, 0)
	conditions := make([]string, 0)
	addCondition := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(args)))
	}
	if filter.Owner != "" {
		addCondition("i.owner = $%d", filter.Owner)
	}
	if filter.Team != "" {
		addCondition("i.team = $%d", filter.Team)
	}
	if filter.Service != "" {
		addCondition("i.service = $%d", filter.Service)
	}
	if filter.Environment != "" {
		addCondition("i.environment = $%d", filter.Environment)
	}
	if filter.IssuerID != "" {
		addCondition("c.issuer_id = $%d", filter.IssuerID)
	}
	if filter.ProfileID != "" {
		addCondition("c.certificate_profile_id = $%d", filter.ProfileID)
	}
	if filter.RevocationState != "" {
		addCondition("c.status = $%d", filter.RevocationState)
	}
	if len(conditions) > 0 {
		query += "\nWHERE " + strings.Join(conditions, " AND ")
	}
	if filter.Sort == "desc" {
		query += "\nORDER BY c.id DESC"
	} else {
		query += "\nORDER BY c.id"
	}
	if filter.Limit > 0 {
		args = append(args, filter.Limit, filter.Offset)
		query += fmt.Sprintf("\nLIMIT $%d OFFSET $%d", len(args)-1, len(args))
	} else if filter.Offset > 0 {
		args = append(args, filter.Offset)
		query += fmt.Sprintf("\nLIMIT 9223372036854775807 OFFSET $%d", len(args))
	}

	rows, err := r.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]CertificateInventoryRecord, 0)
	for rows.Next() {
		record, err := scanCertificateInventoryRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (r sqlRepository) ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error) {
	query := `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE status = $1 AND not_after > $2 AND not_after <= $3
ORDER BY not_after, id`
	args := []any{string(domain.CertificateValid), formatSQLTime(now), formatSQLTime(cutoff)}
	if limit > 0 {
		query += ` LIMIT $4 OFFSET $5`
		args = append(args, limit, offset)
	}
	rows, err := r.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certificates := make([]domain.Certificate, 0)
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (r sqlRepository) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE (
	status IN ($1, $2) AND not_after <= $3
) OR (
	status = $1 AND not_after > $3 AND not_after <= $4 AND renewal_notified_at IS NULL
)
ORDER BY not_after, id
LIMIT $5`,
		string(domain.CertificateValid),
		string(domain.CertificateSuspended),
		formatSQLTime(now),
		formatSQLTime(warningBefore),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certificates := make([]domain.Certificate, 0)
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (r sqlRepository) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	result, err := r.updateCertificate(ctx, certificate, "", false)
	if err != nil {
		return err
	}
	return requireRowsAffected(result, domain.ErrCertificateNotFound)
}

func (r sqlRepository) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	result, err := r.updateCertificate(ctx, certificate, currentStatus, true)
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
	if _, err := r.GetCertificate(ctx, certificate.ID); errors.Is(err, domain.ErrCertificateNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) updateCertificate(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus, requireStatus bool) (sql.Result, error) {
	dnsNames, err := marshalStringSlice(certificate.DNSNames)
	if err != nil {
		return nil, err
	}
	ipAddresses, err := marshalStringSlice(certificate.IPAddresses)
	if err != nil {
		return nil, err
	}

	query := `
UPDATE certificates
SET identity_id = $1,
	issuer_id = $2,
	enrollment_id = $3,
	certificate_profile_id = $4,
	serial_number = $5,
	subject = $6,
	dns_names = $7,
	ip_addresses = $8,
	not_before = $9,
	not_after = $10,
	status = $11,
	certificate_pem = $12,
	renewal_notified_at = $13,
	created_at = $14,
	updated_at = $15
WHERE id = $16`
	args := []any{
		certificate.IdentityID,
		certificate.IssuerID,
		certificate.EnrollmentID,
		certificate.CertificateProfileID,
		certificate.SerialNumber,
		certificate.Subject,
		dnsNames,
		ipAddresses,
		formatSQLTime(certificate.NotBefore),
		formatSQLTime(certificate.NotAfter),
		string(certificate.Status),
		certificate.CertificatePEM,
		formatNullableSQLTime(certificate.RenewalNotifiedAt),
		formatSQLTime(certificate.CreatedAt),
		formatSQLTime(certificate.UpdatedAt),
		certificate.ID,
	}
	if requireStatus {
		query += `
AND status = $17`
		args = append(args, string(currentStatus))
	}
	return r.exec.ExecContext(ctx, query, args...)
}

func (r sqlRepository) CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO certificate_issuance_attempts (
	enrollment_id, status, lease_expires_at, certificate_id, certificate_pem, serial_number, subject,
	not_before, not_after, signing_started_at, signed_at, finalized_at, last_error, signing_evidence_json, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		attempt.EnrollmentID,
		string(attempt.Status),
		formatNullableSQLTime(attempt.LeaseExpiresAt),
		attempt.CertificateID,
		attempt.CertificatePEM,
		attempt.SerialNumber,
		attempt.Subject,
		formatNullableSQLTime(attempt.NotBefore),
		formatNullableSQLTime(attempt.NotAfter),
		formatNullableSQLTime(attempt.SigningStartedAt),
		formatNullableSQLTime(attempt.SignedAt),
		formatNullableSQLTime(attempt.FinalizedAt),
		attempt.LastError,
		attempt.SigningEvidenceJSON,
		formatSQLTime(attempt.CreatedAt),
		formatSQLTime(attempt.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error) {
	attempt, err := scanIssuanceAttempt(r.exec.QueryRowContext(ctx, `
SELECT enrollment_id, status, lease_expires_at, certificate_id, certificate_pem, serial_number, subject,
	not_before, not_after, signing_started_at, signed_at, finalized_at, last_error, signing_evidence_json, created_at, updated_at
FROM certificate_issuance_attempts
WHERE enrollment_id = $1`, enrollmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.IssuanceAttempt{}, domain.ErrIssuanceAttemptNotFound
	}
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	return attempt, nil
}

func (r sqlRepository) UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	currentLeaseExpiresAt := formatNullableSQLTime(current.LeaseExpiresAt)
	result, err := r.exec.ExecContext(ctx, `
UPDATE certificate_issuance_attempts
SET status = $1,
	lease_expires_at = $2,
	certificate_id = $3,
	certificate_pem = $4,
	serial_number = $5,
	subject = $6,
	not_before = $7,
	not_after = $8,
	signing_started_at = $9,
	signed_at = $10,
	finalized_at = $11,
	last_error = $12,
	signing_evidence_json = $13,
	created_at = $14,
	updated_at = $15
WHERE enrollment_id = $16
	AND status = $17
	AND updated_at = $18
	AND lease_expires_at IS NOT DISTINCT FROM $19`,
		string(attempt.Status),
		formatNullableSQLTime(attempt.LeaseExpiresAt),
		attempt.CertificateID,
		attempt.CertificatePEM,
		attempt.SerialNumber,
		attempt.Subject,
		formatNullableSQLTime(attempt.NotBefore),
		formatNullableSQLTime(attempt.NotAfter),
		formatNullableSQLTime(attempt.SigningStartedAt),
		formatNullableSQLTime(attempt.SignedAt),
		formatNullableSQLTime(attempt.FinalizedAt),
		attempt.LastError,
		attempt.SigningEvidenceJSON,
		formatSQLTime(attempt.CreatedAt),
		formatSQLTime(attempt.UpdatedAt),
		attempt.EnrollmentID,
		string(current.Status),
		formatSQLTime(current.UpdatedAt),
		currentLeaseExpiresAt,
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
	if _, err := r.GetIssuanceAttempt(ctx, attempt.EnrollmentID); errors.Is(err, domain.ErrIssuanceAttemptNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO revocations (
	id, certificate_id, reason, revoked_by, revoked_at, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6
)`,
		revocation.ID,
		revocation.CertificateID,
		string(revocation.Reason),
		revocation.RevokedBy,
		formatSQLTime(revocation.RevokedAt),
		formatSQLTime(revocation.CreatedAt),
	)
	return err
}

func (r sqlRepository) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT c.id, c.serial_number, r.revoked_at, r.reason
FROM revocations r
JOIN certificates c ON c.id = r.certificate_id
WHERE c.issuer_id = $1 AND c.status = $2
ORDER BY r.revoked_at, c.serial_number`, issuerID, string(domain.CertificateRevoked))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]domain.RevokedCertificateEntry, 0)
	for rows.Next() {
		entry, err := scanRevokedCertificateEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r sqlRepository) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO crl_publications (
	id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)`,
		publication.ID,
		publication.IssuerID,
		publication.DistributionPoint,
		publication.CRLNumber,
		formatSQLTime(publication.ThisUpdate),
		formatSQLTime(publication.NextUpdate),
		string(publication.Status),
		publication.CRLPEM,
		formatSQLTime(publication.CreatedAt),
		formatSQLTime(publication.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	publication, err := scanCRLPublication(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
FROM crl_publications
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	if err != nil {
		return domain.CRLPublication{}, err
	}
	return publication, nil
}

func (r sqlRepository) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	publication, err := scanCRLPublication(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
FROM crl_publications
WHERE issuer_id = $1
ORDER BY crl_number DESC, created_at DESC, id DESC
LIMIT 1`, issuerID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	if err != nil {
		return domain.CRLPublication{}, err
	}
	return publication, nil
}

func (r sqlRepository) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
FROM crl_publications
WHERE issuer_id = $1
ORDER BY crl_number, created_at, id`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	publications := make([]domain.CRLPublication, 0)
	for rows.Next() {
		publication, err := scanCRLPublication(rows)
		if err != nil {
			return nil, err
		}
		publications = append(publications, publication)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return publications, nil
}

func (r sqlRepository) CreateCRLGenerationClaim(ctx context.Context, claim domain.CRLGenerationClaim) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO crl_generation_claims (
	issuer_id, distribution_point, crl_number, lease_expires_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6
)`,
		claim.IssuerID,
		claim.DistributionPoint,
		claim.CRLNumber,
		formatSQLTime(claim.LeaseExpiresAt),
		formatSQLTime(claim.CreatedAt),
		formatSQLTime(claim.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetCRLGenerationClaim(ctx context.Context, issuerID string, distributionPoint string) (domain.CRLGenerationClaim, error) {
	claim, err := scanCRLGenerationClaim(r.exec.QueryRowContext(ctx, `
SELECT issuer_id, distribution_point, crl_number, lease_expires_at, created_at, updated_at
FROM crl_generation_claims
WHERE issuer_id = $1 AND distribution_point = $2`, issuerID, distributionPoint))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CRLGenerationClaim{}, domain.ErrCRLGenerationClaimNotFound
	}
	if err != nil {
		return domain.CRLGenerationClaim{}, err
	}
	return claim, nil
}

func (r sqlRepository) UpdateCRLGenerationClaimIfCurrent(ctx context.Context, claim domain.CRLGenerationClaim, current domain.CRLGenerationClaim) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE crl_generation_claims
SET crl_number = $1,
	lease_expires_at = $2,
	created_at = $3,
	updated_at = $4
WHERE issuer_id = $5
	AND distribution_point = $6
	AND crl_number = $7
	AND lease_expires_at = $8
	AND updated_at = $9`,
		claim.CRLNumber,
		formatSQLTime(claim.LeaseExpiresAt),
		formatSQLTime(claim.CreatedAt),
		formatSQLTime(claim.UpdatedAt),
		claim.IssuerID,
		claim.DistributionPoint,
		current.CRLNumber,
		formatSQLTime(current.LeaseExpiresAt),
		formatSQLTime(current.UpdatedAt),
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
	if _, err := r.GetCRLGenerationClaim(ctx, claim.IssuerID, claim.DistributionPoint); errors.Is(err, domain.ErrCRLGenerationClaimNotFound) {
		return domain.ErrCRLGenerationClaimNotFound
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) DeleteCRLGenerationClaimIfCurrent(ctx context.Context, current domain.CRLGenerationClaim) error {
	result, err := r.exec.ExecContext(ctx, `
DELETE FROM crl_generation_claims
WHERE issuer_id = $1
	AND distribution_point = $2
	AND crl_number = $3
	AND lease_expires_at = $4
	AND updated_at = $5`,
		current.IssuerID,
		current.DistributionPoint,
		current.CRLNumber,
		formatSQLTime(current.LeaseExpiresAt),
		formatSQLTime(current.UpdatedAt),
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
	if _, err := r.GetCRLGenerationClaim(ctx, current.IssuerID, current.DistributionPoint); errors.Is(err, domain.ErrCRLGenerationClaimNotFound) {
		return domain.ErrCRLGenerationClaimNotFound
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}
