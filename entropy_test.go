package main

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want float64
	}{
		{"empty", "", 0},
		{"single repeated char", "aaaaaaaa", 0},
		{"two equal symbols", "ab", 1.0},
		{"four equal symbols", "abcd", 2.0},
		{"two symbols uneven", "aaab", 0.8112781244591328},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.in)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("shannonEntropy(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"hello", false},      // single class (lower)
		{"HELLO", false},      // single class (upper)
		{"1234567890", false}, // single class (digit)
		{"________", false},   // single class (symbol)
		{"Hello123", true},    // upper+lower+digit
		{"abc123", true},      // lower+digit
		{"ABCdef", true},      // upper+lower
		{"abc-def", true},     // lower+symbol
		{"aB", true},          // upper+lower, minimal
	}
	for _, tt := range tests {
		got := looksLikeSecret(tt.in)
		if got != tt.want {
			t.Errorf("looksLikeSecret(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestLooksLikeFilenameOrURL(t *testing.T) {
	positives := []string{
		"bundle.min.js", "app.css", "vendor.js.map", "logo.PNG",
		"photo.JPEG", "icon.svg", "https://example.com/x", "http://a.b",
		"sourceMappingURL", "font.woff",
	}
	for _, s := range positives {
		if !looksLikeFilenameOrURL(s) {
			t.Errorf("looksLikeFilenameOrURL(%q) = false, want true", s)
		}
	}
	negatives := []string{
		"sk-abcDEF123456", "AKIAIOSFODNN7EXAMPLE", "randomTokenValue99",
	}
	for _, s := range negatives {
		if looksLikeFilenameOrURL(s) {
			t.Errorf("looksLikeFilenameOrURL(%q) = true, want false", s)
		}
	}
}

func TestFindHighEntropyTokens(t *testing.T) {
	// A mixed-class, high-entropy token >= defaultEntropyMinLength (20).
	secret := "aZ9bY8cX7dW6eV5fU4gT3hS2"
	content := "const token = \"" + secret + "\";"

	hits := findHighEntropyTokens(content, 0, 0) // use defaults
	var found bool
	for _, h := range hits {
		if h.Value == secret {
			found = true
			if h.Entropy < defaultEntropyThreshold {
				t.Errorf("entropy %v below threshold %v", h.Entropy, defaultEntropyThreshold)
			}
		}
	}
	if !found {
		t.Errorf("expected to find high-entropy token %q in hits %+v", secret, hits)
	}
}

func TestFindHighEntropyTokensGuardrails(t *testing.T) {
	// Too short (below minLen) must not be flagged.
	if hits := findHighEntropyTokens("abcDEF123", 0, 0); len(hits) != 0 {
		t.Errorf("short token should not be flagged, got %+v", hits)
	}
	// Filename-like token must be rejected even if long and high entropy.
	if hits := findHighEntropyTokens("aZ9bY8cX7dW6eV5fU4gT3h.js", 0, 0); len(hits) != 0 {
		t.Errorf("filename-like token should be rejected, got %+v", hits)
	}
	// Common false positive must be rejected.
	if hits := findHighEntropyTokens("example_aZ9bY8cX7dW6eV5fU4", 0, 0); len(hits) != 0 {
		t.Errorf("false-positive token should be rejected, got %+v", hits)
	}
}

func TestFindHighEntropyTokensDedup(t *testing.T) {
	secret := "aZ9bY8cX7dW6eV5fU4gT3hS2"
	content := secret + " " + secret + " " + secret
	hits := findHighEntropyTokens(content, 0, 0)
	count := 0
	for _, h := range hits {
		if h.Value == secret {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate token should be reported once, got %d", count)
	}
}

func TestFindHighEntropyTokensCap(t *testing.T) {
	// Build content with far more distinct qualifying tokens than the cap.
	var content string
	for i := 0; i < maxEntropyFindingsPerScan+20; i++ {
		// Vary a mixed-class, high-entropy 24-char token per iteration.
		content += "Zq7Wx2Ye5Rt8Up3Ia6Od9Kn" + string(rune('A'+(i%26))) + string(rune('a'+(i%26))) + " "
	}
	hits := findHighEntropyTokens(content, 0, 0)
	if len(hits) > maxEntropyFindingsPerScan {
		t.Errorf("per-scan cap exceeded: got %d, cap %d", len(hits), maxEntropyFindingsPerScan)
	}
}
