package authz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrKeyNotFound means Elasticsearch has no API key with that id.
var ErrKeyNotFound = errors.New("api key not found")

// ES looks up API keys with the authorizer's own credential, an API key with
// the read_security cluster privilege.
type ES struct {
	base   string
	auth   string
	client *http.Client
}

// NewES builds the client. caFile may be empty to use the system roots.
func NewES(baseURL, apiKeyFile, caFile string, timeout time.Duration) (*ES, error) {
	key, err := os.ReadFile(apiKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read API key file: %w", err)
	}
	k := strings.TrimSpace(string(key))
	if k == "" {
		return nil, errors.New("API key file is empty")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file holds no PEM certificates")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &ES{
		base: strings.TrimRight(baseURL, "/"),
		auth: "ApiKey " + k,
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (e *ES) get(ctx context.Context, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", e.auth)
	req.Header.Set("Accept", "application/json")
	res, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	body := io.LimitReader(res.Body, 4<<20)
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, body)
		return res.StatusCode, fmt.Errorf("elasticsearch responded %d for %s", res.StatusCode, path)
	}
	return res.StatusCode, json.NewDecoder(body).Decode(out)
}

// APIKey fetches one key by id, including its role descriptors.
func (e *ES) APIKey(ctx context.Context, id string) (*APIKey, error) {
	var out struct {
		APIKeys []APIKey `json:"api_keys"`
	}
	status, err := e.get(ctx, "/_security/api_key?id="+url.QueryEscape(id), &out)
	if status == http.StatusNotFound {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(out.APIKeys) == 0 {
		return nil, ErrKeyNotFound
	}
	return &out.APIKeys[0], nil
}

// Ready checks that Elasticsearch is reachable and the credential holds
// read_security.
func (e *ES) Ready(ctx context.Context) error {
	var out struct {
		HasAll bool `json:"has_all_requested"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.base+"/_security/user/_has_privileges",
		strings.NewReader(`{"cluster":["read_security"]}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", e.auth)
	req.Header.Set("Content-Type", "application/json")
	res, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("elasticsearch responded %d", res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return err
	}
	if !out.HasAll {
		return errors.New("credential lacks read_security")
	}
	return nil
}
