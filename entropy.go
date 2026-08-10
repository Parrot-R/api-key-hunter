package main

import (
	"math"
	"regexp"
	"strings"
)

// ============================================================================
// ENTROPY-BASED DETECTION
// ============================================================================
//
// Named-prefix regexes (patterns.go) miss high-entropy secrets that don't
// carry a recognizable prefix - bespoke/internal tokens, base64 blobs, hex
// keys, etc. This pass flags candidate tokens whose Shannon entropy exceeds a
// threshold, with guardrails to keep the false-positive rate manageable.

// Default entropy parameters (overridable via config/flags).
const (
	defaultEntropyMinLength = 20
	defaultEntropyThreshold = 4.0
	// maxEntropyFindingsPerScan caps synthetic findings from a single content
	// blob so a large minified bundle can't flood the results.
	maxEntropyFindingsPerScan = 25
)

// entropyTokenRegexp isolates candidate secret-like tokens: runs of characters
// drawn from the alphabets typical of keys/tokens (alnum plus - _ + / . =).
var entropyTokenRegexp = regexp.MustCompile(`[A-Za-z0-9\-_+/.=]{16,120}`)

// shannonEntropy returns the Shannon entropy (bits per character) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// looksLikeSecret applies cheap structural guardrails that reject obviously
// non-secret high-entropy tokens (words, pure numbers, single-charset runs
// that are usually hashes/IDs the user doesn't care about are still allowed
// through, but text with too little character-class diversity is not).
func looksLikeSecret(token string) bool {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	// Require at least two distinct character classes - real keys mix them,
	// while prose words and plain decimal numbers do not.
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			classes++
		}
	}
	return classes >= 2
}

// looksLikeFilenameOrURL rejects high-entropy tokens that are actually asset
// filenames, paths, or URLs - a frequent false-positive source in minified JS.
func looksLikeFilenameOrURL(token string) bool {
	lower := strings.ToLower(token)
	for _, marker := range []string{
		".js", ".map", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".woff", ".ttf", ".html", ".json", ".ico", "http://", "https://",
		"sourcemapping",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// findHighEntropyTokens scans content for high-entropy candidate secrets that
// no named pattern already covers. It returns the distinct token values that
// clear the guardrails, along with their entropy, respecting the per-scan cap.
type entropyHit struct {
	Value   string
	Entropy float64
}

func findHighEntropyTokens(content string, minLen int, threshold float64) []entropyHit {
	if minLen <= 0 {
		minLen = defaultEntropyMinLength
	}
	if threshold <= 0 {
		threshold = defaultEntropyThreshold
	}

	tokens := entropyTokenRegexp.FindAllString(content, -1)
	seen := make(map[string]bool)
	hits := make([]entropyHit, 0)

	for _, tok := range tokens {
		if len(tok) < minLen {
			continue
		}
		if seen[tok] {
			continue
		}
		if isCommonFalsePositive(tok) {
			continue
		}
		if !looksLikeSecret(tok) {
			continue
		}
		// Skip tokens that look like file paths or dotted identifiers.
		if strings.Count(tok, ".") > 3 || strings.Contains(tok, "..") {
			continue
		}
		// Skip tokens that are clearly filenames/URLs rather than secrets
		// (a common source of entropy noise in minified bundles).
		if looksLikeFilenameOrURL(tok) {
			continue
		}
		ent := shannonEntropy(tok)
		if ent < threshold {
			continue
		}
		seen[tok] = true
		hits = append(hits, entropyHit{Value: tok, Entropy: ent})
		if len(hits) >= maxEntropyFindingsPerScan {
			break
		}
	}
	return hits
}
