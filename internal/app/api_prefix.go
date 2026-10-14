package app

import (
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
)

var apiPrefixPattern = regexp.MustCompile(`^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)

func validateAPIPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if !apiPrefixPattern.MatchString(prefix) {
		return fmt.Errorf("use a path such as /google, without a trailing slash, query, or encoded characters")
	}
	first := strings.Split(strings.TrimPrefix(prefix, "/"), "/")[0]
	if first == "v1" || first == "admin" || first == "mcp" {
		return fmt.Errorf("API prefix must not overlap /v1, /admin, or /mcp")
	}
	return nil
}

// Mount only the API under the configured prefix. Strip before secureHandler so
// aliases share the original authentication, body limits and concurrency limit.
// Reject noncanonical paths before ServeMux can redirect them outside the mount.
func apiPrefixHandler(next http.Handler, prefix string) http.Handler {
	if prefix == "" {
		return next
	}
	api := http.StripPrefix(prefix, next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix+"/v1/") || path.Clean(r.URL.Path) != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
}
