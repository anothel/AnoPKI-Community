// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

type ACMEHTTP01Verifier interface {
	VerifyHTTP01(ctx context.Context, identifier string, token string, keyAuthorization string) error
}

type ACMEHTTP01VerifierFunc func(ctx context.Context, identifier string, token string, keyAuthorization string) error

func (f ACMEHTTP01VerifierFunc) VerifyHTTP01(ctx context.Context, identifier string, token string, keyAuthorization string) error {
	return f(ctx, identifier, token, keyAuthorization)
}

var acmeHTTP01BlockedSpecialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func defaultACMEHTTP01Verifier() ACMEHTTP01Verifier {
	verifier, err := NewACMEHTTP01Verifier("")
	if err != nil {
		panic(err)
	}
	return verifier
}

func NewACMEHTTP01Verifier(overrideBaseURL string) (ACMEHTTP01Verifier, error) {
	var baseURL *url.URL
	overrideBaseURL = strings.TrimSpace(overrideBaseURL)
	if overrideBaseURL != "" {
		parsed, err := url.Parse(overrideBaseURL)
		if err != nil {
			return nil, err
		}
		if !acmeHTTP01AllowedScheme(parsed.Scheme) {
			return nil, fmt.Errorf("scheme must be http or https")
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("host is required")
		}
		baseURL = parsed
	}
	client := newACMEHTTP01Client(baseURL == nil)
	return ACMEHTTP01VerifierFunc(func(ctx context.Context, identifier string, token string, keyAuthorization string) error {
		challengeURL := acmeHTTP01ChallengeURL(baseURL, identifier, token)
		if baseURL == nil {
			if err := validateACMEHTTP01FetchURL(&challengeURL); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, challengeURL.String(), nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return domain.ErrInvalidRequest
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(body)) != keyAuthorization {
			return domain.ErrInvalidRequest
		}
		return nil
	}), nil
}

const (
	acmeHTTP01ClientTimeout         = 10 * time.Second
	acmeHTTP01ConnectTimeout        = 5 * time.Second
	acmeHTTP01ResponseHeaderTimeout = 5 * time.Second
	acmeHTTP01RedirectLimit         = 10
)

func newACMEHTTP01Client(guardTargets bool) *http.Client {
	client := &http.Client{Timeout: acmeHTTP01ClientTimeout}
	if !guardTargets {
		return client
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= acmeHTTP01RedirectLimit {
			return domain.ErrInvalidRequest
		}
		return validateACMEHTTP01FetchURL(req.URL)
	}
	dialer := &net.Dialer{Timeout: acmeHTTP01ConnectTimeout}
	client.Transport = &http.Transport{
		ResponseHeaderTimeout: acmeHTTP01ResponseHeaderTimeout,
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, domain.ErrInvalidRequest
			}
			targets, err := acmeHTTP01DialTargets(ctx, host, port, net.DefaultResolver.LookupIPAddr)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, target := range targets {
				conn, err := dialer.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, domain.ErrInvalidRequest
		},
	}
	return client
}

func validateACMEHTTP01FetchURL(fetchURL *url.URL) error {
	if fetchURL == nil ||
		!acmeHTTP01AllowedScheme(fetchURL.Scheme) ||
		fetchURL.Host == "" ||
		fetchURL.User != nil {
		return domain.ErrInvalidRequest
	}
	return validateACMEHTTP01Host(fetchURL.Hostname())
}

func acmeHTTP01AllowedScheme(scheme string) bool {
	return scheme == "http" || scheme == "https"
}

func validateACMEHTTP01Host(host string) error {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return domain.ErrInvalidRequest
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !acmeHTTP01SafeIP(addr.Unmap()) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func acmeHTTP01DialTargets(ctx context.Context, host string, port string, lookup func(context.Context, string) ([]net.IPAddr, error)) ([]string, error) {
	if err := validateACMEHTTP01Host(host); err != nil {
		return nil, err
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !acmeHTTP01SafeIP(addr) {
			continue
		}
		targets = append(targets, net.JoinHostPort(addr.String(), port))
	}
	if len(targets) == 0 {
		return nil, domain.ErrInvalidRequest
	}
	return targets, nil
}

func acmeHTTP01SafeIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if acmeHTTP01BlockedSpecialIP(addr) {
		return false
	}
	return !addr.IsLoopback() &&
		!addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified()
}

func acmeHTTP01BlockedSpecialIP(addr netip.Addr) bool {
	for _, prefix := range acmeHTTP01BlockedSpecialPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return addr == netip.MustParseAddr("169.254.169.254") ||
		addr == netip.MustParseAddr("100.100.100.200")
}

func acmeHTTP01ChallengeURL(baseURL *url.URL, identifier string, token string) url.URL {
	challengePath := "/.well-known/acme-challenge/" + token
	if baseURL == nil {
		return url.URL{
			Scheme: "http",
			Host:   identifier,
			Path:   challengePath,
		}
	}
	challengeURL := *baseURL
	challengeURL.Path = strings.TrimRight(challengeURL.Path, "/") + challengePath
	challengeURL.RawQuery = ""
	challengeURL.Fragment = ""
	return challengeURL
}

