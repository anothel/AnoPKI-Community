// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"net/http"
	"strings"

	"github.com/anothel/anopki/service/internal/observability"
)

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func recordRequestMetric(boundary string, status int) {
	observability.RecordHTTPRequest(boundary, status)
}

func recordEventMetric(key string) {
	observability.RecordEvent(key)
}

func requestMetricBoundary(path string) string {
	switch {
	case path == "/debug/vars":
		return "observability"
	case strings.HasPrefix(path, "/identities"):
		return "identity"
	case strings.HasPrefix(path, "/issuers/") && strings.Contains(path, "/ocsp-responders"):
		return "ocsp_responder"
	case strings.HasPrefix(path, "/issuers/") && strings.HasSuffix(path, "/crl"):
		return "crl"
	case strings.HasPrefix(path, "/issuers"):
		return "issuer"
	case strings.HasPrefix(path, "/certificate-profiles"):
		return "profile"
	case strings.HasPrefix(path, "/enrollments"):
		return "enrollment"
	case path == "/certificates":
		return "issuance"
	case strings.Contains(path, "/revoke"):
		return "revocation"
	case strings.Contains(path, "/renew"):
		return "renewal"
	case strings.Contains(path, "/reissue"):
		return "reissue"
	case strings.Contains(path, "/suspend") || strings.Contains(path, "/resume"):
		return "suspension"
	case strings.HasPrefix(path, "/certificates/expiration-scan"):
		return "expiration_scan"
	case strings.HasPrefix(path, "/certificates"):
		return "certificate"
	case strings.HasPrefix(path, "/crls"):
		return "crl"
	case path == "/ocsp":
		return "ocsp"
	case strings.HasPrefix(path, "/acme"):
		return "acme"
	case strings.HasPrefix(path, "/notification-endpoints"):
		return "webhook"
	case strings.HasPrefix(path, "/outbox"):
		return "outbox"
	case strings.HasPrefix(path, "/api-keys"):
		return "auth"
	case strings.HasPrefix(path, "/audit-events"):
		return "audit"
	case strings.HasPrefix(path, "/operator"):
		return "operator"
	default:
		return "http"
	}
}
