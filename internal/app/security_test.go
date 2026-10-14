package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func securityConfig(t *testing.T) {
	t.Helper()
	old := cfg
	cfg = defaultConfig()
	cfg.DBPath = old.DBPath
	t.Cleanup(func() { cfg = old })
}

func TestAdminTokenDefaultIsPrivateAndPersistent(t *testing.T) {
	securityConfig(t)
	if cfg.Host != "127.0.0.1" {
		t.Fatal("default listener must be loopback")
	}
	cfg.DBPath = filepath.Join(t.TempDir(), "state", "gemini.db")
	path, err := initAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	token := cfg.AdminToken
	if len(token) != 64 {
		t.Fatal("expected a random 256-bit token")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatal("token file is not private")
	}
	cfg.AdminToken = ""
	if _, err := initAdminToken(); err != nil {
		t.Fatal(err)
	}
	if cfg.AdminToken != token {
		t.Fatal("token must survive restart")
	}
	cfg.AdminToken = "change-me-in-production"
	if _, err := initAdminToken(); err == nil {
		t.Fatal("accepted a weak placeholder")
	}
}

func TestAdminAndAPIAuthFailClosed(t *testing.T) {
	securityConfig(t)
	oldKey := getAPIKey()
	apiKeyRuntime.Store("sk-security-test-only")
	t.Cleanup(func() { apiKeyRuntime.Store(oldKey) })
	for _, token := range []string{"", strings.Repeat("x", 64)} {
		cfg.AdminToken = token
		w := httptest.NewRecorder()
		requireAuth(handleAdminAPIKey)(w, httptest.NewRequest("GET", "/admin/api/apikey", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated status=%d", w.Code)
		}
		if strings.Contains(w.Body.String(), "sk-security-test-only") {
			t.Fatal("API key leaked")
		}
	}
	r := httptest.NewRequest("GET", "/admin/api/apikey?token="+cfg.AdminToken, nil)
	if authOK(r) {
		t.Fatal("tokens in URLs must not authenticate")
	}
	r.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	if !authOK(r) {
		t.Fatal("valid bearer rejected")
	}
	apiKeyRuntime.Store("")
	w := httptest.NewRecorder()
	requireAPIKey(func(http.ResponseWriter, *http.Request) { t.Fatal("missing API key opened endpoint") })(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal(w.Code)
	}
}

func TestAdminRejectsCrossOriginAndDoesNotExposeCORS(t *testing.T) {
	securityConfig(t)
	cfg.AdminToken = strings.Repeat("x", 64)
	h := secureHandler(requireAuth(handleAdminAPIKey))
	for _, origin := range []string{"https://attacker.example", "null", "http://localhost.evil"} {
		r := httptest.NewRequest("GET", "http://localhost/admin/api/apikey", nil)
		r.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("origin=%s status=%d", origin, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("admin CORS exposed")
		}
	}
	r := httptest.NewRequest("GET", "http://localhost/admin/api/apikey", nil)
	r.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	r.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("same-origin access failed")
	}
}

type countingSecurityBody struct{ remaining, consumed int }

func (r *countingSecurityBody) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	r.remaining -= n
	r.consumed += n
	return n, nil
}

func TestLoginRejectsOversizedChunkedBodyBeforeReadingItAll(t *testing.T) {
	securityConfig(t)
	cfg.AdminToken = strings.Repeat("x", 64)
	body := &countingSecurityBody{remaining: 16 << 20}
	r := httptest.NewRequest("POST", "/admin/api/login", body)
	w := httptest.NewRecorder()
	handleAdminLogin(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || body.consumed > maxLoginBodyBytes+1 {
		t.Fatalf("status=%d bytes read=%d", w.Code, body.consumed)
	}
}

func TestLoginRequiresTokenAndSetsSafeSessionCookie(t *testing.T) {
	securityConfig(t)
	w := httptest.NewRecorder()
	handleAdminLogin(w, httptest.NewRequest("POST", "/admin/api/login", strings.NewReader(`{"token":""}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("empty admin token authenticated")
	}
	cfg.AdminToken = strings.Repeat("x", 64)
	r := httptest.NewRequest("POST", "https://localhost/admin/api/login", strings.NewReader(`{"token":"`+cfg.AdminToken+`"}`))
	r.TLS = &tls.ConnectionState{}
	w = httptest.NewRecorder()
	handleAdminLogin(w, r)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("session cookie protections missing")
	}
	r = httptest.NewRequest("GET", "/admin/api/apikey", nil)
	r.AddCookie(cookies[0])
	if !authOK(r) {
		t.Fatal("valid session rejected")
	}
	var rawSessions int
	if err := getDB().QueryRow("SELECT COUNT(*) FROM sessions WHERE token=?", cookies[0].Value).Scan(&rawSessions); err != nil || rawSessions != 0 {
		t.Fatal("session cookie stored without hashing")
	}
	cfg.AdminToken = strings.Repeat("y", 64)
	if authOK(r) {
		t.Fatal("old session survived an admin token change")
	}
}

func TestRequestBodyLimitsCoverAPIEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		limit   int64
	}{
		{"chat", handleChatCompletions, maxAPIBodyBytes},
		{"responses", handleResponses, maxAPIBodyBytes},
		{"videos", handleCreateVideo, maxAdminBodyBytes},
		{"mcp", handleMCPHTTP, 8 << 20},
		{"cookies", handleAdminCookies, maxAdminBodyBytes},
		{"config", handleAdminConfig, maxAdminBodyBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := "POST"
			if tc.name == "config" {
				method = "PUT"
			}
			r := httptest.NewRequest(method, "/", strings.NewReader("{}"))
			r.ContentLength = tc.limit + 1
			w := httptest.NewRecorder()
			tc.handler(w, r)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

func frameWithURLs(urls ...string) string {
	payload, _ := json.Marshal([]any{nil, nil, nil, nil, []any{[]any{"rc_review", urls}}})
	frame, _ := json.Marshal([]any{[]any{"wrb.fr", nil, string(payload)}})
	return string(frame)
}

func TestMediaURLExtractionRejectsSpoofedHosts(t *testing.T) {
	good := "https://lh3.googleusercontent.com/gg-dl/example"
	urls := []string{good,
		"http://lh3.googleusercontent.com/gg-dl/example",
		"https://attacker.example/lh3.googleusercontent.com/gg-dl/example",
		"https://lh3.googleusercontent.com.attacker.example/gg-dl/example",
		"https://lh3.googleusercontent.com@attacker.example/gg-dl/example",
		"https://attacker.example/?next=https://lh3.googleusercontent.com/gg-dl/example",
		"https://lh3.googleusercontent.com:444/gg-dl/example",
	}
	got := collectImageURLs(frameWithURLs(urls...))
	if len(got) != 1 || got[0] != good {
		t.Fatalf("accepted untrusted URLs: %v", got)
	}
	if got := collectDownloadURLs(frameWithURLs("https://attacker.example/contribution.usercontent.google.com/download")); len(got) != 0 {
		t.Fatal("spoofed music/video URL accepted")
	}
}

type securityRoundTrip func(*http.Request) (*http.Response, error)

func (f securityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMediaRedirectChecksDestinationBeforeSendingCookies(t *testing.T) {
	const proxy = "http://security-test.invalid"
	for _, target := range []string{"https://attacker.example/leak", "http://lh3.googleusercontent.com/gg-dl/a", "http://127.0.0.1/private", "https://work.fife.usercontent.google.com/rd-gg-dl/a"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			stdlibClientCache.Store(proxy, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Cookie") != "SID=dummy; SAPISID=dummy" {
					t.Fatal("incorrect cookie filtering")
				}
				if calls == 1 {
					return &http.Response{StatusCode: 302, Header: http.Header{"Location": {target}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				if r.URL.Hostname() != "work.fife.usercontent.google.com" {
					t.Fatal("cookies reached untrusted host")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"image/png"}}, Body: io.NopCloser(strings.NewReader("image")), Request: r}, nil
			})})
			t.Cleanup(func() { stdlibClientCache.Delete(proxy) })
			_, _, err := downloadBytes("https://lh3.googleusercontent.com/gg-dl/a", "SID=dummy; SAPISID=dummy; __Host-1PLSID=host-only", proxy, "image/png")
			allowed := strings.HasPrefix(target, "https://work.fife.")
			if allowed && (err != nil || calls != 2) {
				t.Fatalf("legitimate redirect failed: %v", err)
			}
			if !allowed && (err == nil || calls != 1) {
				t.Fatalf("untrusted redirect attempted: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestUntrustedMediaAndUploadNeverMakeRequest(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	headers := map[string]string{"Cookie": "SID=dummy"}
	if _, _, _, err := mediaGetOnce(srv.URL+"/lh3.googleusercontent.com/gg-dl/a", headers, ""); err == nil {
		t.Fatal("untrusted media accepted")
	}
	if _, _, _, err := uploadPost(srv.URL, headers, []byte("private"), ""); err == nil {
		t.Fatal("untrusted upload accepted")
	}
	if _, err := materializeImage(srv.URL, "", 1); err == nil {
		t.Fatal("loopback input accepted")
	}
	if called {
		t.Fatal("local service received a request")
	}
}

type securityResolver struct {
	ips   []netip.Addr
	calls int
}

func (r *securityResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	return r.ips, nil
}

func TestPublicMediaDialPinsDNSAndRejectsPrivateAnswers(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "::ffff:127.0.0.1", "fd00::1", "fe80::1", "64:ff9b::7f00:1", "2002:7f00:1::"} {
		if publicMediaIP(netip.MustParseAddr(ip)) {
			t.Fatalf("accepted private/special address %s", ip)
		}
	}
	for _, ips := range [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")},
	} {
		r := &securityResolver{ips: ips}
		_, err := publicMediaDialer(r, func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dialed a private DNS answer")
			return nil, nil
		})(context.Background(), "tcp", "images.example:443")
		if err == nil {
			t.Fatal("private DNS accepted")
		}
	}
	r := &securityResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	_, _ = publicMediaDialer(r, func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Fatalf("did not dial pinned IP: %s", address)
		}
		return nil, fmt.Errorf("test dial stopped")
	})(context.Background(), "tcp", "images.example:443")
	if r.calls != 1 {
		t.Fatal("DNS was resolved again")
	}
}

func TestRemoteMediaRejectsNonImageResponses(t *testing.T) {
	old := publicMediaClient
	t.Cleanup(func() { publicMediaClient = old })
	publicMediaClient = &http.Client{Timeout: time.Second, Transport: securityRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("input download has credentials")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("private service data")), Request: r}, nil
	})}
	if _, err := fetchImage("https://images.example/file", "", 1); err == nil {
		t.Fatal("text relabeled as an image")
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1/private", nil)
	if err := old.CheckRedirect(r, []*http.Request{{}}); err == nil {
		t.Fatal("redirect to private address accepted")
	}
}

func TestPrivateDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "gemini.db")
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := preparePrivateDatabase(path); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not private", name)
		}
	}
}

func TestVideoJobsBoundActiveWorkAndRetainedResults(t *testing.T) {
	old := videoJobs
	videoJobs = map[string]*videoJob{}
	t.Cleanup(func() { videoJobs = old })
	for i := 0; i < 20; i++ {
		if !putVideoJob(&videoJob{ID: fmt.Sprint(i), CreatedAt: time.Now().Unix(), Status: "completed"}) {
			t.Fatal("completed results prevented new jobs")
		}
		if len(videoJobs) > 8 {
			t.Fatal("video cache grew beyond its limit")
		}
	}
	for i := 0; i < 2; i++ {
		if !putVideoJob(&videoJob{ID: fmt.Sprintf("active-%d", i), CreatedAt: time.Now().Unix(), Status: "queued"}) {
			t.Fatal("job rejected before limit")
		}
	}
	if putVideoJob(&videoJob{ID: "excess", CreatedAt: time.Now().Unix(), Status: "queued"}) {
		t.Fatal("active job limit exceeded")
	}
	snapshot := getVideoJob("active-0")
	finishVideoJob(videoJobs["active-0"], nil, "", "test failure")
	if snapshot.Status != "queued" {
		t.Fatal("job snapshot shares mutable state")
	}
}

func TestRequestConcurrencyIsBoundedAndSlotsReleased(t *testing.T) {
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	done := make(chan struct{}, 8)
	h := apiPrefixHandler(secureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})), "/google")
	for i := 0; i < 8; i++ {
		requestPath := "/v1/chat/completions"
		if i%2 == 0 {
			requestPath = "/google" + requestPath
		}
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", requestPath, nil))
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-started
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/google/v1/chat/completions", nil))
	close(release)
	for i := 0; i < 8; i++ {
		<-done
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatal("excess request was admitted")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if w.Code != http.StatusOK {
		t.Fatal("request slot was not released")
	}
}
