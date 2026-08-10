package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// LIVE KEY VALIDATION
// ============================================================================
//
// Opt-in (--validate). For key types with a documented, non-destructive
// "who am I" style endpoint, issue a single authenticated read request using
// the discovered key to determine whether it is actually live. This is exactly
// what makes a secret dangerous: a valid, working credential vs. a dead or
// example string.
//
// SAFETY: This uses a found credential against a third-party API, so it is
// gated behind --validate and an explicit authorization banner in main(). Every
// validator issues only a read-only call (list/whoami/balance) - never a
// mutation. Unsupported key types return a clear "unsupported" outcome, never a
// false negative.

// validationOutcome is the result of one validation attempt.
type validationOutcome struct {
	Supported bool
	Live      bool
	Detail    string
}

// KeyValidator performs and caches live-key checks.
type KeyValidator struct {
	httpClient *http.Client
	cache      map[string]validationOutcome
	cacheMutex sync.Mutex
}

func NewKeyValidator() *KeyValidator {
	return &KeyValidator{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      make(map[string]validationOutcome),
	}
}

// Validate checks a single finding's key against its provider, if supported.
func (v *KeyValidator) Validate(ctx context.Context, keyType, keyValue string) validationOutcome {
	cacheKey := keyType + ":" + keyValue
	v.cacheMutex.Lock()
	if cached, ok := v.cache[cacheKey]; ok {
		v.cacheMutex.Unlock()
		return cached
	}
	v.cacheMutex.Unlock()

	outcome := v.dispatch(ctx, keyType, keyValue)

	v.cacheMutex.Lock()
	v.cache[cacheKey] = outcome
	v.cacheMutex.Unlock()
	return outcome
}

// dispatch routes a key to the right provider check based on its detected type.
func (v *KeyValidator) dispatch(ctx context.Context, keyType, keyValue string) validationOutcome {
	switch {
	case strings.HasPrefix(keyType, "OpenAI"):
		return v.checkBearer(ctx, "https://api.openai.com/v1/models", keyValue)
	case keyType == "GitHub PAT", keyType == "GitHub Fine-grained Token":
		return v.checkGitHub(ctx, keyValue)
	case keyType == "GitLab Token":
		return v.checkGitLab(ctx, keyValue)
	case keyType == "Stripe Secret Key":
		return v.checkStripe(ctx, keyValue)
	case keyType == "Slack Token":
		return v.checkSlack(ctx, keyValue)
	case keyType == "SendGrid API Key":
		return v.checkBearer(ctx, "https://api.sendgrid.com/v3/scopes", keyValue)
	default:
		return validationOutcome{Supported: false, Detail: "validation unsupported for this key type"}
	}
}

// checkBearer issues a GET with an Authorization: Bearer header and treats a
// 2xx as live, 401/403 as dead, anything else as inconclusive.
func (v *KeyValidator) checkBearer(ctx context.Context, endpoint, key string) validationOutcome {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return validationOutcome{Supported: true, Detail: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	return v.classify(v.httpClient.Do(req))
}

func (v *KeyValidator) checkGitHub(ctx context.Context, key string) validationOutcome {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return validationOutcome{Supported: true, Detail: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/vnd.github+json")
	return v.classify(v.httpClient.Do(req))
}

func (v *KeyValidator) checkGitLab(ctx context.Context, key string) validationOutcome {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://gitlab.com/api/v4/user", nil)
	if err != nil {
		return validationOutcome{Supported: true, Detail: err.Error()}
	}
	req.Header.Set("PRIVATE-TOKEN", key)
	return v.classify(v.httpClient.Do(req))
}

func (v *KeyValidator) checkStripe(ctx context.Context, key string) validationOutcome {
	// GET /v1/balance is read-only and requires a valid secret key.
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return validationOutcome{Supported: true, Detail: err.Error()}
	}
	req.SetBasicAuth(key, "")
	return v.classify(v.httpClient.Do(req))
}

func (v *KeyValidator) checkSlack(ctx context.Context, key string) validationOutcome {
	// auth.test is Slack's canonical read-only token check.
	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/auth.test",
		strings.NewReader(url.Values{"token": {key}}.Encode()))
	if err != nil {
		return validationOutcome{Supported: true, Detail: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return validationOutcome{Supported: true, Detail: fmt.Sprintf("request error: %v", err)}
	}
	defer resp.Body.Close()
	// Slack always returns HTTP 200; the body's "ok" field carries the verdict.
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if strings.Contains(body, "\"ok\":true") {
		return validationOutcome{Supported: true, Live: true, Detail: "slack auth.test ok"}
	}
	return validationOutcome{Supported: true, Live: false, Detail: "slack auth.test not ok"}
}

// classify maps an HTTP response to a validation outcome and closes the body.
func (v *KeyValidator) classify(resp *http.Response, err error) validationOutcome {
	if err != nil {
		return validationOutcome{Supported: true, Detail: fmt.Sprintf("request error: %v", err)}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return validationOutcome{Supported: true, Live: true, Detail: fmt.Sprintf("HTTP %d - key is live", resp.StatusCode)}
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return validationOutcome{Supported: true, Live: false, Detail: fmt.Sprintf("HTTP %d - key rejected", resp.StatusCode)}
	default:
		return validationOutcome{Supported: true, Live: false, Detail: fmt.Sprintf("HTTP %d - inconclusive", resp.StatusCode)}
	}
}

// isSyntheticKeyType reports whether a finding is a marker/heuristic type with
// no provider API to validate against (as opposed to a real named credential).
func isSyntheticKeyType(keyType string) bool {
	switch keyType {
	case "High-Entropy String", "Git Repository Exposure", "Exposed Sensitive File":
		return true
	}
	return false
}

// runValidation validates every finding in place using a small worker pool.
// Only real named keys are attempted (entropy/git-exposure findings are
// skipped). It mutates findings under findingsMutex, mirroring the AI pass.
func runValidation(workers int) {
	if workers <= 0 {
		workers = 5
	}
	validator := NewKeyValidator()

	type job struct{ idx int }
	jobs := make(chan job, len(findings))

	findingsMutex.Lock()
	for i := range findings {
		// Synthetic findings (entropy blobs, exposure markers) have no provider
		// endpoint to validate against; real keys found inside an exposed file
		// still get validated by their KeyType.
		if isSyntheticKeyType(findings[i].KeyType) {
			continue
		}
		jobs <- job{idx: i}
	}
	findingsMutex.Unlock()
	close(jobs)

	var wgLocal sync.WaitGroup
	for w := 0; w < workers; w++ {
		wgLocal.Add(1)
		go func() {
			defer wgLocal.Done()
			for j := range jobs {
				findingsMutex.Lock()
				keyType := findings[j.idx].KeyType
				keyValue := findings[j.idx].Value
				findingsMutex.Unlock()

				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				outcome := validator.Validate(ctx, keyType, keyValue)
				cancel()

				findingsMutex.Lock()
				findings[j.idx].Validated = outcome.Supported
				findings[j.idx].Live = outcome.Live
				findings[j.idx].ValidationDetail = outcome.Detail
				findingsMutex.Unlock()

				if outcome.Live {
					fmt.Printf("🔥 [LIVE KEY] %s confirmed active: %s\n", keyType, outcome.Detail)
				}
			}
		}()
	}
	wgLocal.Wait()
}
