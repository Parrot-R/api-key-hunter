package main

import "testing"

// TestDefaultPatternsMatch checks that each pattern matches a representative
// sample. This guards against an accidental regex edit silently breaking a
// detector. Samples are synthetic, not real credentials.
func TestDefaultPatternsMatch(t *testing.T) {
	samples := map[string]string{
		"OpenAI API Key (Legacy)":  "sk-" + rep("a", 20) + "T3BlbkFJ" + rep("b", 20),
		"OpenAI API Key (New)":     "sk-proj-" + rep("a", 48),
		"Anthropic Claude API Key": "sk-ant-api03-" + rep("a", 95),
		"Google AI Studio API Key": "AIza" + rep("A", 35),
		"Hugging Face Token":       "hf_" + rep("a", 34),
		"AWS Access Key":           "AKIA" + rep("A", 16),
		"GitHub PAT":               "ghp_" + rep("a", 36),
		"Stripe Secret Key":        "sk_live_" + rep("a", 24),
		"JWT Token":                "eyJ" + rep("a", 10) + "." + rep("b", 10) + "." + rep("c", 10),
		"Private Key Block":        "-----BEGIN RSA PRIVATE KEY-----",
		"Slack Token":              "xoxb-" + rep("a", 20),
	}

	byName := make(map[string]APIKeyPattern)
	for _, p := range defaultPatterns() {
		byName[p.Name] = p
	}

	for name, sample := range samples {
		p, ok := byName[name]
		if !ok {
			t.Errorf("pattern %q not found in defaultPatterns()", name)
			continue
		}
		if !p.Pattern.MatchString(sample) {
			t.Errorf("pattern %q did not match its sample %q", name, sample)
		}
	}
}

func TestDefaultPatternsCompileAndHaveSeverity(t *testing.T) {
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	seen := make(map[string]bool)
	for _, p := range defaultPatterns() {
		if p.Name == "" {
			t.Error("pattern with empty name")
		}
		if p.Pattern == nil {
			t.Errorf("pattern %q has nil regexp", p.Name)
		}
		if !valid[p.Severity] {
			t.Errorf("pattern %q has invalid severity %q", p.Name, p.Severity)
		}
		if seen[p.Name] {
			t.Errorf("duplicate pattern name %q", p.Name)
		}
		seen[p.Name] = true
	}
}

func TestLooksLikeGitConfig(t *testing.T) {
	positives := []string{
		"[core]\n\trepositoryformatversion = 0",
		"[remote \"origin\"]\n\turl = x",
		"ref: refs/heads/main",
		"DIRC\x00\x00\x00\x02",
	}
	for _, b := range positives {
		if !looksLikeGitConfig(b) {
			t.Errorf("looksLikeGitConfig(%q) = false, want true", b)
		}
	}
	negatives := []string{
		"<html></html>",
		"just some text",
		"",
	}
	for _, b := range negatives {
		if looksLikeGitConfig(b) {
			t.Errorf("looksLikeGitConfig(%q) = true, want false", b)
		}
	}
}

func TestFilterPatterns(t *testing.T) {
	all := []APIKeyPattern{
		{Name: "A"}, {Name: "B"}, {Name: "C"},
	}

	// No enable/disable: all pass through.
	if got := filterPatterns(all, nil, nil); len(got) != 3 {
		t.Errorf("empty filters: got %d patterns, want 3", len(got))
	}

	// Enable only B and C.
	got := filterPatterns(all, []string{"B", "C"}, nil)
	if len(got) != 2 || got[0].Name != "B" || got[1].Name != "C" {
		t.Errorf("enable [B,C]: got %+v", names(got))
	}

	// Disable B.
	got = filterPatterns(all, nil, []string{"B"})
	if len(got) != 2 || got[0].Name != "A" || got[1].Name != "C" {
		t.Errorf("disable [B]: got %+v", names(got))
	}

	// Disable wins over enable for the same name.
	got = filterPatterns(all, []string{"A", "B"}, []string{"B"})
	if len(got) != 1 || got[0].Name != "A" {
		t.Errorf("enable [A,B] disable [B]: got %+v", names(got))
	}
}

func rep(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func names(ps []APIKeyPattern) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}
