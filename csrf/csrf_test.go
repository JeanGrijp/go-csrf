package csrf

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func tokenEndpointHandler(p *Protector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
		p.TokenHandler().ServeHTTP(w, r)
	})
	return p.Protect(mux)
}

func appHandler(p *Protector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	return p.Protect(mux)
}

func getCookieByName(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Ensures that a safe method sets the CSRF cookie and that TokenHandler returns the same value.
func TestSafeMethodSetsCookieAndContext(t *testing.T) {
	cfg := Config{
		CookieName: "csrf_token_test",
		TokenBytes: 16,
	}
	p := New(cfg)

	h := tokenEndpointHandler(p)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)

	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	tokenFromHandler := strings.TrimSpace(string(body))
	if tokenFromHandler == "" {
		t.Fatalf("expected non-empty token body")
	}

	cookie := getCookieByName(res, cfg.CookieName)
	if cookie == nil {
		t.Fatalf("expected Set-Cookie %q", cfg.CookieName)
	}
	if cookie.Value != tokenFromHandler {
		t.Fatalf("token mismatch: cookie=%q handler=%q", cookie.Value, tokenFromHandler)
	}
}

// Validates that POST requires a matching token (header) when EnforceOriginCheck is disabled.
func TestPostRequiresMatchingToken(t *testing.T) {
	cfg := Config{
		CookieName: "csrf_token_test",
		HeaderName: "X-CSRF-Token",
		TokenBytes: 16,
		// Origin check off in this test
		EnforceOriginCheck: false,
	}
	p := New(cfg)

	// First, GET the token
	tokenRec := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	tokenHandler := tokenEndpointHandler(p)
	tokenHandler.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()
	cookie := getCookieByName(tokenRes, cfg.CookieName)
	if cookie == nil {
		t.Fatalf("missing csrf cookie")
	}
	tokenBytes, _ := io.ReadAll(tokenRes.Body)
	token := strings.TrimSpace(string(tokenBytes))

	// Now, POST with correct token
	app := appHandler(p)
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("{}"))
	reqOK.Header.Set("Content-Type", "application/json")
	reqOK.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	reqOK.Header.Set(cfg.HeaderName, token)
	app.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d", recOK.Code)
	}

	// And with wrong token
	recBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("{}"))
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	reqBad.Header.Set(cfg.HeaderName, "wrong-token")
	app.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with wrong token, got %d", recBad.Code)
	}
}

// When EnforceOriginCheck is true, Origin/Referer must match same-site policy.
func TestOriginCheck(t *testing.T) {
	cfg := Config{
		CookieName:         "csrf_token_test",
		HeaderName:         "X-CSRF-Token",
		TokenBytes:         16,
		EnforceOriginCheck: true,
		// AllowedOrigin empty -> use r.Host
	}
	p := New(cfg)

	// Bootstrap: get token and cookie via GET
	tokenRec := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	tokenHandler := tokenEndpointHandler(p)
	tokenHandler.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()
	cookie := getCookieByName(tokenRes, cfg.CookieName)
	if cookie == nil {
		t.Fatalf("missing csrf cookie")
	}
	tokenBytes, _ := io.ReadAll(tokenRes.Body)
	token := strings.TrimSpace(string(tokenBytes))

	app := appHandler(p)

	// Matching origin (same as host)
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodPost, "/submit", nil)
	reqOK.Host = "example.com"
	reqOK.Header.Set("Origin", "https://example.com")
	reqOK.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	reqOK.Header.Set(cfg.HeaderName, token)
	app.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with matching origin, got %d", recOK.Code)
	}

	// Mismatching origin
	recBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodPost, "/submit", nil)
	reqBad.Host = "example.com"
	reqBad.Header.Set("Origin", "https://evil.com")
	reqBad.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	reqBad.Header.Set(cfg.HeaderName, token)
	app.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with mismatching origin, got %d", recBad.Code)
	}
}

// Validates that POST can provide the token via form field (x-www-form-urlencoded).
func TestPostWithFormFieldToken(t *testing.T) {
	cfg := Config{
		CookieName: "csrf_token_test",
		HeaderName: "X-CSRF-Token",
		FormField:  "csrf_token",
		TokenBytes: 16,
	}
	p := New(cfg)

	// Get token and cookie first
	tokenRec := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	tokenHandler := tokenEndpointHandler(p)
	tokenHandler.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()
	cookie := getCookieByName(tokenRes, cfg.CookieName)
	if cookie == nil {
		t.Fatalf("missing csrf cookie")
	}
	tokenBytes, _ := io.ReadAll(tokenRes.Body)
	token := strings.TrimSpace(string(tokenBytes))

	// Now POST with form field carrying the token
	app := appHandler(p)
	form := url.Values{}
	form.Set(cfg.FormField, token)
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	reqOK.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqOK.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	app.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct form token, got %d", recOK.Code)
	}

	// Wrong form token
	formBad := url.Values{}
	formBad.Set(cfg.FormField, "wrong")
	recBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(formBad.Encode()))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBad.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	app.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with wrong form token, got %d", recBad.Code)
	}
}

// Ensures cookie attributes honor configuration (path, domain, samesite, maxAge, secure, httpOnly=false).
func TestCookieAttributes(t *testing.T) {
	cfg := Config{
		CookieName:     "csrf_token_test",
		CookiePath:     "/custom",
		CookieDomain:   "example.com",
		CookieSecure:   true,
		CookieSameSite: http.SameSiteStrictMode,
		CookieMaxAge:   3600,
		TokenBytes:     16,
	}
	p := New(cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	tokenEndpointHandler(p).ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	c := getCookieByName(res, cfg.CookieName)
	if c == nil {
		t.Fatalf("expected Set-Cookie %q", cfg.CookieName)
	}
	if c.Path != cfg.CookiePath {
		t.Fatalf("cookie path mismatch: got %q want %q", c.Path, cfg.CookiePath)
	}
	if c.Domain != cfg.CookieDomain {
		t.Fatalf("cookie domain mismatch: got %q want %q", c.Domain, cfg.CookieDomain)
	}
	if c.SameSite != cfg.CookieSameSite {
		t.Fatalf("cookie samesite mismatch: got %v want %v", c.SameSite, cfg.CookieSameSite)
	}
	if c.MaxAge != cfg.CookieMaxAge {
		t.Fatalf("cookie maxage mismatch: got %d want %d", c.MaxAge, cfg.CookieMaxAge)
	}
	if !c.Secure {
		t.Fatalf("cookie should be Secure")
	}
	if c.HttpOnly {
		t.Fatalf("cookie should be HttpOnly=false for double-submit")
	}
}

// Validates Referer is accepted when Origin is empty and matches the host (same-site).
func TestRefererCheck(t *testing.T) {
	cfg := Config{
		CookieName:         "csrf_token_test",
		HeaderName:         "X-CSRF-Token",
		TokenBytes:         16,
		EnforceOriginCheck: true,
	}
	p := New(cfg)

	// GET token
	tokenRec := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	tokenHandler := tokenEndpointHandler(p)
	tokenHandler.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()
	cookie := getCookieByName(tokenRes, cfg.CookieName)
	if cookie == nil {
		t.Fatalf("missing csrf cookie")
	}
	tokenBytes, _ := io.ReadAll(tokenRes.Body)
	token := strings.TrimSpace(string(tokenBytes))

	app := appHandler(p)

	// Accept matching referer when origin is empty
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodPost, "/submit", nil)
	reqOK.Host = "example.com"
	reqOK.Header.Set("Referer", "https://example.com/page")
	reqOK.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	reqOK.Header.Set(cfg.HeaderName, token)
	app.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with matching referer, got %d", recOK.Code)
	}

	// Reject mismatching referer
	recBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodPost, "/submit", nil)
	reqBad.Host = "example.com"
	reqBad.Header.Set("Referer", "https://evil.com/page")
	reqBad.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	reqBad.Header.Set(cfg.HeaderName, token)
	app.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with mismatching referer, got %d", recBad.Code)
	}
}
