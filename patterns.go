package main

import "regexp"

// ============================================================================
// SECRET PATTERNS
// ============================================================================

// APIKeyPattern represents a pattern for detecting API keys
type APIKeyPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Severity    string // "critical", "high", "medium", "low"
}

// defaultPatterns returns every built-in secret-detection pattern.
//
// If a pattern's regex has a capture group, checkForKeys uses match[1] as the
// key value instead of the full match (for patterns like `api_key: "..."`
// where only the value, not the surrounding field name, should be reported).
func defaultPatterns() []APIKeyPattern {
	return []APIKeyPattern{
		// AI & Machine Learning APIs
		{"OpenAI API Key (Legacy)", regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}`), "OpenAI legacy format", "critical"},
		{"OpenAI API Key (New)", regexp.MustCompile(`sk-proj-[a-zA-Z0-9-_]{48,}`), "OpenAI project key", "critical"},
		{"Anthropic Claude API Key", regexp.MustCompile(`sk-ant-api03-[a-zA-Z0-9\-_]{95,}`), "Anthropic Claude", "critical"},
		{"Google AI Studio API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "Google AI/Cloud", "critical"},
		{"Hugging Face Token", regexp.MustCompile(`hf_[a-zA-Z0-9]{34,}`), "Hugging Face", "high"},
		{"Replicate API Token", regexp.MustCompile(`r8_[a-zA-Z0-9]{40,}`), "Replicate AI", "high"},
		{"Perplexity AI Key", regexp.MustCompile(`pplx-[a-zA-Z0-9]{32,}`), "Perplexity AI", "high"},

		// Cloud & Infrastructure
		{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID", "critical"},
		{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`), "AWS Secret", "critical"},
		{"GitHub PAT", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub Personal Access Token", "critical"},
		{"GitHub Fine-grained Token", regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`), "GitHub Fine-grained PAT", "critical"},
		{"GitLab Token", regexp.MustCompile(`glpat-[a-zA-Z0-9-_]{20,}`), "GitLab Personal Access Token", "critical"},
		{"DigitalOcean Token", regexp.MustCompile(`dop_v1_[a-f0-9]{64}`), "DigitalOcean API Token", "critical"},
		{"Azure Storage Account Key", regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/]{86}==)`), "Azure Storage connection-string key", "critical"},
		{"GCP Service Account Key", regexp.MustCompile(`"type":\s*"service_account"[\s\S]{0,400}?"private_key_id":\s*"[a-f0-9]{40}"`), "GCP service account JSON key", "critical"},
		{"Terraform Cloud Token", regexp.MustCompile(`[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,}`), "Terraform Cloud/Enterprise API Token", "critical"},
		{"CircleCI Token", regexp.MustCompile(`(?i)circleci[_-]?token['"]?\s*[:=]\s*['"]?([a-fA-F0-9]{40})['"]?`), "CircleCI Personal API Token", "high"},

		// Payment & Services
		{"Stripe Secret Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "Stripe Live Secret Key", "critical"},
		{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[a-zA-Z0-9]{24,}`), "Stripe Live Publishable Key", "medium"},
		{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`), "Slack API Token", "high"},
		{"Discord Token", regexp.MustCompile(`[0-9]{18}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}`), "Discord Bot Token", "high"},
		{"Mailgun API Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), "Mailgun API Key", "high"},
		{"Twilio API Key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`), "Twilio API Key", "high"},
		{"SendGrid API Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), "SendGrid API Key", "high"},
		{"Shopify API Key", regexp.MustCompile(`shppa_[a-f0-9]{32}`), "Shopify API Key", "high"},
		{"Square Access Token", regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`), "Square OAuth Access Token", "high"},

		// Dev Tooling & Package Registries
		{"npm Access Token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), "npm registry access token", "high"},
		{"Docker Hub PAT", regexp.MustCompile(`dckr_pat_[a-zA-Z0-9_-]{27,}`), "Docker Hub Personal Access Token", "high"},
		{"PyPI Upload Token", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`), "PyPI upload API token", "high"},
		{"Postman API Key", regexp.MustCompile(`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`), "Postman API Key", "high"},

		// Observability & Search
		{"New Relic License Key", regexp.MustCompile(`NRAK-[A-Z0-9]{27}`), "New Relic License Key", "high"},
		{"Datadog API Key", regexp.MustCompile(`(?i)datadog[_-]?api[_-]?key['"]?\s*[:=]\s*['"]?([a-f0-9]{32})['"]?`), "Datadog API Key", "high"},
		{"Algolia Admin API Key", regexp.MustCompile(`(?i)algolia[_-]?(admin[_-]?)?api[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?`), "Algolia Admin API Key", "high"},
		{"Cloudflare API Token", regexp.MustCompile(`(?i)cloudflare[_-]?(api[_-]?)?token['"]?\s*[:=]\s*['"]?([A-Za-z0-9_-]{40})['"]?`), "Cloudflare API Token", "high"},
		{"Cloudflare Global API Key", regexp.MustCompile(`(?i)cloudflare[_-]?(global[_-]?)?api[_-]?key['"]?\s*[:=]\s*['"]?([a-f0-9]{37})['"]?`), "Cloudflare Global API Key", "critical"},
		{"Heroku API Key", regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key['"]?\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`), "Heroku API Key", "high"},

		// Generic Tokens
		{"Generic API Key", regexp.MustCompile(`(?i)api[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?`), "Generic API Key pattern", "medium"},
		{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "JSON Web Token", "high"},
		{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.?[a-zA-Z0-9\-_=]*)`), "Bearer Token", "high"},
		{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "Private Key", "critical"},
	}
}

// filterPatterns applies a config-driven allow/deny list to a pattern set by
// Name. An empty enable list means "all patterns enabled"; disable is applied
// after enable and always wins for a name present in both.
func filterPatterns(all []APIKeyPattern, enable, disable []string) []APIKeyPattern {
	disabled := make(map[string]bool, len(disable))
	for _, name := range disable {
		disabled[name] = true
	}

	var enabled map[string]bool
	if len(enable) > 0 {
		enabled = make(map[string]bool, len(enable))
		for _, name := range enable {
			enabled[name] = true
		}
	}

	result := make([]APIKeyPattern, 0, len(all))
	for _, p := range all {
		if disabled[p.Name] {
			continue
		}
		if enabled != nil && !enabled[p.Name] {
			continue
		}
		result = append(result, p)
	}
	return result
}
