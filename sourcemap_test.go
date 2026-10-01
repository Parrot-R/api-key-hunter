package main

import (
	"reflect"
	"testing"
)

func TestExtractSourceMapURLsAnnotation(t *testing.T) {
	body := "console.log(1)\n//# sourceMappingURL=app.js.map\n"
	got := extractSourceMapURLs(body, "https://example.com/js/app.js")
	want := []string{"https://example.com/js/app.js.map"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extractSourceMapURLs = %v, want %v", got, want)
	}
}

func TestExtractSourceMapURLsSkipsDataURI(t *testing.T) {
	// Use a non-.js base so the convention fallback does not fire; this
	// isolates the data-URI skip and proves it yields no fetchable URL.
	body := "//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ==\n"
	if got := extractSourceMapURLs(body, "https://example.com/bundle.mjs"); len(got) != 0 {
		t.Errorf("data-URI map should be skipped, got %v", got)
	}
}

func TestExtractSourceMapURLsConventionFallback(t *testing.T) {
	// No annotation but a .js URL -> conventional sibling .map.
	got := extractSourceMapURLs("var x = 1;", "https://example.com/app.js")
	want := []string{"https://example.com/app.js.map"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fallback = %v, want %v", got, want)
	}
	// Non-.js URL with no annotation -> nothing.
	if got := extractSourceMapURLs("body{}", "https://example.com/app.css"); len(got) != 0 {
		t.Errorf("non-js fallback should be empty, got %v", got)
	}
}

func TestExtractSourceMapURLsInvalidBase(t *testing.T) {
	if got := extractSourceMapURLs("//# sourceMappingURL=a.map", "://bad url"); got != nil {
		t.Errorf("invalid base should return nil, got %v", got)
	}
}

func TestLooksLikeSourceMap(t *testing.T) {
	// .map extension (query ignored).
	if !looksLikeSourceMap("https://x/app.js.map?v=1", "") {
		t.Error(".map URL should be recognized")
	}
	// JSON body with mappings field.
	if !looksLikeSourceMap("https://x/blob", `{"version":3,"mappings":"AAAA"}`) {
		t.Error("body with mappings should be recognized")
	}
	// JSON body with sourcesContent field.
	if !looksLikeSourceMap("https://x/blob", `{"sourcesContent":["x"]}`) {
		t.Error("body with sourcesContent should be recognized")
	}
	// Plain JS, non-.map URL.
	if looksLikeSourceMap("https://x/app.js", "var x = 1;") {
		t.Error("plain JS should not be recognized as a source map")
	}
	// JSON-looking but without map fields.
	if looksLikeSourceMap("https://x/data", `{"foo":"bar"}`) {
		t.Error("unrelated JSON should not be recognized as a source map")
	}
}
