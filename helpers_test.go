package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestMaskKey(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "****"},
		{"short", "****"},
		{"12345678", "****"}, // exactly 8 -> masked fully
		{"abcd1234ef", "abcd**34ef"},
		{"0123456789abcdef", "0123********cdef"},
	}
	for _, tt := range tests {
		got := maskKey(tt.in)
		if got != tt.want {
			t.Errorf("maskKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
		// Masked output never equals the full secret for longer keys.
		if len(tt.in) > 8 && got == tt.in {
			t.Errorf("maskKey(%q) leaked the full key", tt.in)
		}
	}
}

func TestMaskKeyPreservesLength(t *testing.T) {
	key := "AKIAIOSFODNN7EXAMPLE"
	if got := maskKey(key); len(got) != len(key) {
		t.Errorf("maskKey changed length: %d vs %d", len(got), len(key))
	}
}

func TestMaskKeyForAI(t *testing.T) {
	// Short branch (<= 12).
	if got := maskKeyForAI("abcdefghij"); got != "abc***hij" {
		t.Errorf("maskKeyForAI short = %q, want abc***hij", got)
	}
	// Long branch includes prefix, suffix, and length.
	got := maskKeyForAI("0123456789abcdefghij")
	if !strings.HasPrefix(got, "01234567") || !strings.Contains(got, "length: 20") {
		t.Errorf("maskKeyForAI long = %q", got)
	}
}

func TestTruncateContext(t *testing.T) {
	if got := truncateContext("  hello  ", 10); got != "hello" {
		t.Errorf("no truncation = %q", got)
	}
	if got := truncateContext("abcdefghij", 5); got != "abcde..." {
		t.Errorf("truncation = %q, want abcde...", got)
	}
}

func TestExtractContext(t *testing.T) {
	content := "prefix KEYVALUE suffix"
	got := extractContext(content, "KEYVALUE", 3)
	if got != "ix KEYVALUE su" {
		t.Errorf("extractContext = %q", got)
	}
	// Missing key -> empty.
	if got := extractContext(content, "ABSENT", 3); got != "" {
		t.Errorf("extractContext missing = %q, want empty", got)
	}
	// Window clamps at content boundaries.
	if got := extractContext("KEY", "KEY", 100); got != "KEY" {
		t.Errorf("extractContext clamp = %q, want KEY", got)
	}
}

func TestIsCommonFalsePositive(t *testing.T) {
	positives := []string{
		"EXAMPLE_KEY", "my-sample-token", "testtoken", "placeholder",
		"your_api_key", "xxxxx", "DUMMY", "fakeKey", "demo123", "<token>",
	}
	for _, s := range positives {
		if !isCommonFalsePositive(s) {
			t.Errorf("isCommonFalsePositive(%q) = false, want true", s)
		}
	}
	negatives := []string{
		"AKIAIOSFODNN7REALKEY", "sk-prod-abc123", "legitValue99",
	}
	for _, s := range negatives {
		if isCommonFalsePositive(s) {
			t.Errorf("isCommonFalsePositive(%q) = true, want false", s)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,c ", []string{"a", "b", "c"}},
		{"a,,b,", []string{"a", "b"}},
		{"  ", []string{}}, // only the empty string short-circuits to nil
	}
	for _, tt := range tests {
		got := splitCSV(tt.in)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestMatchesExtension(t *testing.T) {
	// Empty list matches everything.
	if !matchesExtension("https://x/a.php", nil) {
		t.Error("empty extensions should match everything")
	}
	exts := []string{".js", ".json"}
	cases := map[string]bool{
		"https://x/app.js":         true,
		"https://x/app.js?v=123":   true, // query stripped
		"https://x/data.json#frag": true, // fragment stripped
		"https://x/App.JS":         true, // case-insensitive
		"https://x/style.css":      false,
		"https://x/page":           false,
	}
	for url, want := range cases {
		if got := matchesExtension(url, exts); got != want {
			t.Errorf("matchesExtension(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestSarifLevel(t *testing.T) {
	cases := map[string]string{
		"critical": "error",
		"high":     "error",
		"medium":   "warning",
		"low":      "note",
		"unknown":  "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestIsSyntheticKeyType(t *testing.T) {
	synthetic := []string{"High-Entropy String", "Git Repository Exposure", "Exposed Sensitive File"}
	for _, s := range synthetic {
		if !isSyntheticKeyType(s) {
			t.Errorf("isSyntheticKeyType(%q) = false, want true", s)
		}
	}
	if isSyntheticKeyType("AWS Access Key") {
		t.Error("named key type should not be synthetic")
	}
}
