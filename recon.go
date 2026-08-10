package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// RECON / SEED GATHERING
// ============================================================================
//
// Before crawling, gather extra seed URLs and in-scope hosts from passive OSINT
// sources and the target's own robots.txt/sitemap. This surfaces pages that are
// archived, unlinked, or on sibling subdomains - places live-only link-follow
// crawling never reaches. Every source is best-effort: a slow or blocked source
// (crt.sh and the Wayback Machine are notoriously flaky) logs a warning and is
// skipped, and must never abort the scan.

// ReconOptions controls which sources are consulted.
type ReconOptions struct {
	Wayback        bool
	OTX            bool
	OTXKey         string
	CrtSh          bool
	ActiveRecon    bool // probe sensitive paths (.env, .git/config, ...)
	SubdomainScope bool // whether discovered hosts widen the crawl scope
}

// reconResult is the aggregate output of the seeding phase.
type reconResult struct {
	SeedURLs   []string
	Subdomains []string
}

// reconClient is a short-timeout client shared by all source lookups.
var reconClient = &http.Client{Timeout: 20 * time.Second}

// crtShClient gets a longer timeout - crt.sh is chronically slow.
var crtShClient = &http.Client{Timeout: 45 * time.Second}

// gatherSeeds runs every enabled source and returns deduplicated seed URLs and
// discovered subdomains for the given target URL.
func gatherSeeds(targetURL string, opts ReconOptions) reconResult {
	base, err := url.Parse(targetURL)
	if err != nil {
		return reconResult{}
	}
	domain := base.Hostname()

	urlSet := make(map[string]bool)
	hostSet := make(map[string]bool)

	// Always seed robots.txt + sitemap of the target itself.
	for _, u := range fetchRobotsSitemap(base) {
		urlSet[u] = true
	}

	if opts.Wayback {
		urls, err := fetchWaybackURLs(domain)
		if err != nil {
			fmt.Printf("⚠️  Wayback source skipped: %v\n", err)
		}
		for _, u := range urls {
			urlSet[u] = true
		}
	}

	if opts.OTX {
		urls, hosts, err := fetchOTXURLs(domain, opts.OTXKey)
		if err != nil {
			fmt.Printf("⚠️  OTX url_list source skipped: %v\n", err)
		}
		for _, u := range urls {
			urlSet[u] = true
		}
		for _, h := range hosts {
			hostSet[h] = true
		}
		if opts.OTXKey != "" {
			hosts, err := fetchOTXPassiveDNS(domain, opts.OTXKey)
			if err != nil {
				fmt.Printf("⚠️  OTX passive_dns source skipped: %v\n", err)
			}
			for _, h := range hosts {
				hostSet[h] = true
			}
		}
	}

	if opts.CrtSh {
		hosts, err := fetchCrtShSubdomains(domain)
		if err != nil {
			fmt.Printf("⚠️  crt.sh source skipped: %v\n", err)
		}
		for _, h := range hosts {
			hostSet[h] = true
		}
	}

	// Active recon: probe a sensitive-path wordlist against every in-scope host
	// (the target plus any discovered subdomains, when subdomain scope is on).
	// base.Host preserves any explicit port on the target; discovered
	// subdomains are bare hostnames (default port).
	if opts.ActiveRecon {
		hosts := []string{base.Host}
		if opts.SubdomainScope {
			for h := range hostSet {
				hosts = append(hosts, h)
			}
		}
		for _, u := range expandSensitivePaths(base.Scheme, hosts) {
			urlSet[u] = true
		}
	}

	return reconResult{
		SeedURLs:   sortedKeys(urlSet),
		Subdomains: sortedKeys(hostSet),
	}
}

// fetchRobotsSitemap parses robots.txt for Disallow paths and Sitemap
// declarations, then pulls <loc> entries from any referenced sitemaps.
func fetchRobotsSitemap(base *url.URL) []string {
	var out []string
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", base.Scheme, base.Host)
	body, err := httpGetString(reconClient, robotsURL, nil)
	if err != nil {
		return out
	}

	var sitemaps []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"):
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" && path != "/" && !strings.Contains(path, "*") {
				if abs, err := base.Parse(path); err == nil {
					out = append(out, abs.String())
				}
			}
		case strings.HasPrefix(lower, "sitemap:"):
			sm := strings.TrimSpace(line[len("sitemap:"):])
			if sm != "" {
				sitemaps = append(sitemaps, sm)
			}
		}
	}

	// Fall back to the conventional sitemap location.
	if len(sitemaps) == 0 {
		sitemaps = append(sitemaps, fmt.Sprintf("%s://%s/sitemap.xml", base.Scheme, base.Host))
	}

	locRegexp := regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
	for _, sm := range sitemaps {
		smBody, err := httpGetString(reconClient, sm, nil)
		if err != nil {
			continue
		}
		for _, m := range locRegexp.FindAllStringSubmatch(smBody, -1) {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return out
}

// fetchWaybackURLs pulls historical URLs for a domain from the Wayback Machine
// CDX API. The response is a JSON array of arrays whose first row is a header.
func fetchWaybackURLs(domain string) ([]string, error) {
	endpoint := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s*&output=json&fl=original&collapse=urlkey&limit=5000",
		url.QueryEscape(domain))
	body, err := httpGetBytes(reconClient, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parse wayback response: %w", err)
	}

	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header row
			continue
		}
		out = append(out, row[0])
	}
	return out, nil
}

// fetchOTXURLs pulls URLs (and their hostnames) for a domain from OTX
// AlienVault's anonymous url_list endpoint, paging until exhausted or capped.
func fetchOTXURLs(domain, apiKey string) (urls []string, hosts []string, err error) {
	hostSet := make(map[string]bool)
	const maxPages = 10
	for page := 1; page <= maxPages; page++ {
		endpoint := fmt.Sprintf(
			"https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=%d",
			url.QueryEscape(domain), page)
		var headers map[string]string
		if apiKey != "" {
			headers = map[string]string{"X-OTX-API-KEY": apiKey}
		}
		body, e := httpGetBytes(reconClient, endpoint, headers)
		if e != nil {
			if page == 1 {
				return urls, hosts, e
			}
			break // partial results are fine
		}

		var resp struct {
			HasNext bool `json:"has_next"`
			URLList []struct {
				URL      string `json:"url"`
				Hostname string `json:"hostname"`
			} `json:"url_list"`
		}
		if e := json.Unmarshal(body, &resp); e != nil {
			return urls, hosts, fmt.Errorf("parse otx response: %w", e)
		}
		if len(resp.URLList) == 0 {
			break
		}
		for _, item := range resp.URLList {
			if item.URL != "" {
				urls = append(urls, item.URL)
			}
			if item.Hostname != "" && strings.HasSuffix(item.Hostname, domain) {
				hostSet[item.Hostname] = true
			}
		}
		if !resp.HasNext {
			break
		}
	}
	return urls, sortedKeys(hostSet), nil
}

// fetchOTXPassiveDNS returns subdomains from OTX passive DNS records. This
// endpoint requires an API key.
func fetchOTXPassiveDNS(domain, apiKey string) ([]string, error) {
	endpoint := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns",
		url.QueryEscape(domain))
	body, err := httpGetBytes(reconClient, endpoint, map[string]string{"X-OTX-API-KEY": apiKey})
	if err != nil {
		return nil, err
	}

	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse otx passive_dns: %w", err)
	}

	hostSet := make(map[string]bool)
	for _, rec := range resp.PassiveDNS {
		if rec.Hostname != "" && strings.HasSuffix(rec.Hostname, domain) {
			hostSet[rec.Hostname] = true
		}
	}
	return sortedKeys(hostSet), nil
}

// fetchCrtShSubdomains enumerates subdomains from crt.sh certificate
// transparency logs. crt.sh is slow and frequently times out, so this is
// strictly best-effort.
func fetchCrtShSubdomains(domain string) ([]string, error) {
	endpoint := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	body, err := httpGetBytes(crtShClient, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parse crt.sh response: %w", err)
	}

	hostSet := make(map[string]bool)
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" && strings.HasSuffix(name, domain) {
				hostSet[name] = true
			}
		}
	}
	return sortedKeys(hostSet), nil
}

// sensitivePaths is the wordlist of commonly-exposed secret-bearing files probed
// during active recon.
func sensitivePaths() []string {
	return []string{
		".env", ".env.local", ".env.production", ".env.backup", ".env.bak",
		".git/config", ".git/HEAD", ".git/index",
		"config.json", "config.js", "config.yml", "config.yaml",
		"settings.py", "application.properties", "appsettings.json",
		"wp-config.php.bak", "wp-config.php~", "web.config",
		"credentials", ".aws/credentials", ".npmrc", ".dockercfg",
		"docker-compose.yml", "docker-compose.yaml",
		"secrets.json", "secrets.yml", "id_rsa", ".ssh/id_rsa",
		"backup.sql", "dump.sql", "database.yml",
	}
}

// expandSensitivePaths joins the wordlist onto each host to produce probe URLs.
func expandSensitivePaths(scheme string, hosts []string) []string {
	if scheme == "" {
		scheme = "https"
	}
	var out []string
	for _, host := range hosts {
		for _, p := range sensitivePaths() {
			out = append(out, fmt.Sprintf("%s://%s/%s", scheme, host, p))
		}
	}
	return out
}

// isSensitivePathURL reports whether rawURL targets one of the sensitive-path
// wordlist entries, so response handling can flag exposure findings.
func isSensitivePathURL(rawURL string) (string, bool) {
	path := rawURL
	if idx := strings.IndexAny(path, "?#"); idx != -1 {
		path = path[:idx]
	}
	for _, p := range sensitivePaths() {
		if strings.HasSuffix(path, "/"+p) {
			return p, true
		}
	}
	return "", false
}

// ---- small HTTP helpers ----

func httpGetBytes(client *http.Client, endpoint string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "api-hunter-recon")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 25<<20)) // 25 MB cap
}

func httpGetString(client *http.Client, endpoint string, headers map[string]string) (string, error) {
	b, err := httpGetBytes(client, endpoint, headers)
	return string(b), err
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
