package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOAuth2HTTPClientDisablesHTTP2 pins the #671 fix: the OIDC HTTP client
// must force HTTP/1.1 (so it can't hang on the Cloudflare HTTP/2 token POST)
// and must carry a non-zero timeout.
func TestOAuth2HTTPClientDisablesHTTP2(t *testing.T) {
	client := oauth2HTTPClient()

	if client.Timeout <= 0 {
		t.Fatalf("expected a non-zero timeout, got %v", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 must be false to keep connections on HTTP/1.1")
	}
	// A non-nil TLSNextProto map is what actually disables the HTTP/2 upgrade.
	if tr.TLSNextProto == nil {
		t.Error("TLSNextProto must be non-nil (empty) to disable HTTP/2")
	}
	if len(tr.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto must be empty, has %d entries", len(tr.TLSNextProto))
	}
}

// TestOAuth2HTTPClientBoundsHangingServer is the behavioural guarantee behind
// #671: against a server that never responds, the client returns an error
// within its timeout rather than hanging the login request forever.
func TestOAuth2HTTPClientBoundsHangingServer(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until the test tears down
	}))
	// LIFO: release the handler first, then shut the server.
	defer srv.Close()
	defer close(block)

	client := oauth2HTTPClientWithTimeout(200 * time.Millisecond)

	start := time.Now()
	resp, err := client.Get(srv.URL)
	elapsed := time.Since(start)

	if err == nil {
		resp.Body.Close()
		t.Fatal("expected a timeout error from a hanging server, got nil")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("request was not bounded by the timeout: took %v", elapsed)
	}
}
