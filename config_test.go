package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveString(t *testing.T) {
	// explicit flag always wins
	if got := resolveString(true, "flag", "cfg"); got != "flag" {
		t.Errorf("explicit: got %q, want flag", got)
	}
	// not explicit, cfg set -> cfg
	if got := resolveString(false, "flag", "cfg"); got != "cfg" {
		t.Errorf("cfg set: got %q, want cfg", got)
	}
	// not explicit, cfg empty -> flag default
	if got := resolveString(false, "flag", ""); got != "flag" {
		t.Errorf("cfg empty: got %q, want flag", got)
	}
}

func TestResolveInt(t *testing.T) {
	if got := resolveInt(true, 5, 9); got != 5 {
		t.Errorf("explicit: got %d, want 5", got)
	}
	if got := resolveInt(false, 5, 9); got != 9 {
		t.Errorf("cfg set: got %d, want 9", got)
	}
	if got := resolveInt(false, 5, 0); got != 5 {
		t.Errorf("cfg zero: got %d, want 5", got)
	}
}

func TestResolveFloat(t *testing.T) {
	if got := resolveFloat(true, 1.5, 9.5); got != 1.5 {
		t.Errorf("explicit: got %v, want 1.5", got)
	}
	if got := resolveFloat(false, 1.5, 9.5); got != 9.5 {
		t.Errorf("cfg set: got %v, want 9.5", got)
	}
	if got := resolveFloat(false, 1.5, 0); got != 1.5 {
		t.Errorf("cfg zero: got %v, want 1.5", got)
	}
}

func TestResolveBool(t *testing.T) {
	// explicit always wins (even when false)
	if got := resolveBool(true, false, true); got != false {
		t.Errorf("explicit false: got %v, want false", got)
	}
	// not explicit -> cfg value
	if got := resolveBool(false, false, true); got != true {
		t.Errorf("cfg true: got %v, want true", got)
	}
}

func TestResolveStrings(t *testing.T) {
	flagVal := []string{"a"}
	cfgVal := []string{"b", "c"}
	if got := resolveStrings(true, flagVal, cfgVal); !reflect.DeepEqual(got, flagVal) {
		t.Errorf("explicit: got %v, want %v", got, flagVal)
	}
	if got := resolveStrings(false, flagVal, cfgVal); !reflect.DeepEqual(got, cfgVal) {
		t.Errorf("cfg set: got %v, want %v", got, cfgVal)
	}
	if got := resolveStrings(false, flagVal, nil); !reflect.DeepEqual(got, flagVal) {
		t.Errorf("cfg empty: got %v, want %v", got, flagVal)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `url: https://example.com
depth: 4
formats: [json, html, sarif]
domains: [example.com, cdn.example.com]
entropy:
  enabled: true
  threshold: 4.0
sources:
  wayback: true
  otx: true
ai:
  provider: anthropic
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.URL != "https://example.com" {
		t.Errorf("URL = %q", cfg.URL)
	}
	if cfg.Depth != 4 {
		t.Errorf("Depth = %d", cfg.Depth)
	}
	if !reflect.DeepEqual(cfg.Formats, []string{"json", "html", "sarif"}) {
		t.Errorf("Formats = %v", cfg.Formats)
	}
	if !cfg.Entropy.Enabled || cfg.Entropy.Threshold != 4.0 {
		t.Errorf("Entropy = %+v", cfg.Entropy)
	}
	if !cfg.Sources.Wayback || !cfg.Sources.OTX {
		t.Errorf("Sources = %+v", cfg.Sources)
	}
	if cfg.AI.Provider != "anthropic" {
		t.Errorf("AI.Provider = %q", cfg.AI.Provider)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("url: [unterminated\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Error("expected error for malformed YAML")
	}
}
