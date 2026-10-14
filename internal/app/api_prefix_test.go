package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIPrefixValidation(t *testing.T) {
	for _, prefix := range []string{"", "/google", "/providers/google-v1"} {
		if err := validateAPIPrefix(prefix); err != nil {
			t.Fatalf("valid prefix %q: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"/", "google", "/google/", "/google//api", "/google/..", "/google?x=1", "/%67oogle", "/v1", "/admin/google", "/mcp"} {
		if validateAPIPrefix(prefix) == nil {
			t.Fatalf("invalid prefix accepted: %q", prefix)
		}
	}
}

func TestAPIPrefixPreservesAuthenticationBodyQueryAndStreaming(t *testing.T) {
	oldKey := getAPIKey()
	apiKeyRuntime.Store("prefix-test-key")
	t.Cleanup(func() { apiKeyRuntime.Store(oldKey) })
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", requireAPIKey(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.URL.RawQuery != "trace=one%2Ftwo" {
			t.Fatalf("incorrect upstream URL: %s", r.URL)
		}
		body, ok := readRequestBody(w, r, maxAPIBodyBytes)
		if !ok {
			return
		}
		if string(body) != `{"stream":true}` {
			t.Fatalf("body changed: %q", body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: OK\n\n")
		w.(http.Flusher).Flush()
	}))
	h := apiPrefixHandler(secureHandler(mux), "/google")
	for _, prefix := range []string{"", "/google"} {
		for _, key := range []string{"", "wrong-key", "prefix-test-key"} {
			r := httptest.NewRequest("POST", prefix+"/v1/chat/completions?trace=one%2Ftwo", strings.NewReader(`{"stream":true}`))
			if key != "" {
				r.Header.Set("Authorization", "Bearer "+key)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if key != "prefix-test-key" {
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("%s: unauthorized status %d", prefix, w.Code)
				}
				continue
			}
			if w.Code != http.StatusOK || !w.Flushed || w.Body.String() != "data: OK\n\n" {
				t.Fatalf("%s: streaming failed: status=%d flushed=%v body=%q", prefix, w.Code, w.Flushed, w.Body.String())
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("alias bypassed security middleware")
			}
		}
	}
	r := httptest.NewRequest("POST", "/google/v1/chat/completions?trace=one%2Ftwo", nil)
	r.ContentLength = maxAPIBodyBytes + 1
	r.Header.Set("x-api-key", "prefix-test-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("alias bypassed body limit: %d", w.Code)
	}
}

func TestAPIPrefixCannotReachAdminOrEscapeMount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "private admin") })
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "local MCP") })
	h := apiPrefixHandler(secureHandler(mux), "/google")
	for _, target := range []string{
		"/google", "/google/", "/google/admin/", "/google/admin/api/cookies", "/google/mcp",
		"/google/v1/../admin/", "/google/v1/../../admin/", "/google/v1/%2e%2e/admin/",
		"/google/v1//models", "/google/v1/%2fadmin/", "/google/v1/./models",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != http.StatusNotFound || w.Header().Get("Location") != "" {
			t.Fatalf("%s escaped mount: status=%d location=%q", target, w.Code, w.Header().Get("Location"))
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/", nil))
	if w.Code != http.StatusOK || w.Body.String() != "private admin" {
		t.Fatal("local admin route was changed")
	}
}
