package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// ============================================================================
// SOURCE MAP EXTRACTION
// ============================================================================
//
// Minified JS bundles routinely reference a source map (//# sourceMappingURL=)
// whose "sourcesContent" array embeds the *original*, unminified source -
// comments, variable names, and often hard-coded secrets that survive
// minification only inside the map. Fetching and scanning these is one of the
// highest-yield ways to find leaked keys on a modern site.

// sourceMappingURLRegexp captures the target of a //# sourceMappingURL= (or the
// older //@ form) annotation. Data-URI maps are handled separately.
var sourceMappingURLRegexp = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=(\S+)`)

// extractSourceMapURLs returns absolute URLs of source maps referenced by a JS
// body served from baseURL. It resolves the annotated URL against baseURL and,
// as a fallback for bundles that omit the annotation, also offers the
// conventional "<script>.js.map" sibling. Inline data: URIs are skipped here
// (they're decoded and scanned directly by the caller).
func extractSourceMapURLs(body, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var urls []string
	add := func(raw string) {
		if raw == "" || seen[raw] {
			return
		}
		seen[raw] = true
		urls = append(urls, raw)
	}

	for _, m := range sourceMappingURLRegexp.FindAllStringSubmatch(body, -1) {
		ref := strings.TrimSpace(m[1])
		if strings.HasPrefix(ref, "data:") {
			// Inline data-URI maps are embedded in the JS body already scanned
			// by the caller; skip fetching them as a separate URL.
			continue
		}
		if abs, err := base.Parse(ref); err == nil {
			add(abs.String())
		}
	}

	// Convention-based fallback: app.js -> app.js.map (only for .js URLs that
	// didn't already advertise a map).
	if len(urls) == 0 && strings.HasSuffix(base.Path, ".js") {
		add(baseURL + ".map")
	}

	return urls
}

// looksLikeSourceMap reports whether a response body is a JS source map, so the
// OnResponse handler can route it to scanSourceMap even when the content-type
// is generic (source maps are frequently served as application/octet-stream).
func looksLikeSourceMap(rawURL, body string) bool {
	if strings.HasSuffix(strings.SplitN(rawURL, "?", 2)[0], ".map") {
		return true
	}
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	return strings.Contains(trimmed, "\"sourcesContent\"") || strings.Contains(trimmed, "\"mappings\"")
}

// sourceMapDoc is the subset of the Source Map v3 format we consume.
type sourceMapDoc struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// scanSourceMap parses a source map body and runs the standard key detection
// over each embedded original-source entry, attributing findings to mapURL.
func scanSourceMap(mapURL, body string, patterns []APIKeyPattern) {
	var doc sourceMapDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return
	}
	for i, src := range doc.SourcesContent {
		if src == "" {
			continue
		}
		label := mapURL
		if i < len(doc.Sources) && doc.Sources[i] != "" {
			label = mapURL + " (" + doc.Sources[i] + ")"
		}
		checkForKeysWithSource(label, src, patterns, "sourcemap")
	}
}
