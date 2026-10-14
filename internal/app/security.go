package app

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxLoginBodyBytes  = 4 << 10
	maxAdminBodyBytes  = 1 << 20
	maxAPIBodyBytes    = 72 << 20 // Allows one 50 MiB base64 video plus JSON.
	maxArtifactBytes   = 100 << 20
	maxAttachmentBytes = 64 << 20
	maxAttachments     = 16
)

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("body exceeds %d-byte limit", limit)
	}
	return b, nil
}

func readRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if r.ContentLength > limit {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": "invalid or oversized request body"})
		return nil, false
	}
	return body, true
}

// These limits apply before parsing bodies or downloading any attachments.
func secureHandler(next http.Handler) http.Handler {
	requests := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			if !sameOriginAdminRequest(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin admin request denied"})
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/mcp" {
			select {
			case requests <- struct{}{}:
				defer func() { <-requests }()
			default:
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many concurrent requests"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOriginAdminRequest(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") &&
			u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" &&
			strings.EqualFold(u.Host, r.Host)
	}
	return true // Non-browser clients still require a token.
}

// Never start an open admin panel. When not explicitly configured, persist a
// random token beside the database and show only its file path in the banner.
func initAdminToken() (string, error) {
	if !cfg.AdminEnabled {
		return "", nil
	}
	if cfg.AdminToken != "" {
		return "", validateAdminToken(cfg.AdminToken)
	}
	path := filepath.Join(filepath.Dir(cfg.DBPath), "admin-token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		token := newSessionToken()
		_, writeErr := io.WriteString(f, token+"\n")
		closeErr := f.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		cfg.AdminToken = token
		return path, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("admin token must be a regular file: %s", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	f, err = os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := readBounded(f, maxLoginBodyBytes)
	if err != nil {
		return "", err
	}
	cfg.AdminToken = strings.TrimSpace(string(b))
	return path, validateAdminToken(cfg.AdminToken)
}

func validateAdminToken(token string) error {
	if len(strings.TrimSpace(token)) < 32 || len(token) > 1024 {
		return fmt.Errorf("admin token must contain 32–1024 characters; leave it unset to generate a random token")
	}
	return nil
}

// Cookies and API keys must be readable only by the service owner. SQLite
// creates its WAL/SHM files with the database's mode, so secure it before open.
func preparePrivateDatabase(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("database files must be regular files: %s", name)
		}
		if err := os.Chmod(name, 0o600); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}
