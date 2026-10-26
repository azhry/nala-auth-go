package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionClientValidatesBearerAndPreservesPrincipal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/auth/session" {
			t.Fatalf("request = %s %s, want GET /api/auth/session", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer session-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"authenticated":true,"user":{"id":"account-123","name":"Ada","email":"ada@example.test","tier":"admin","entitlements":{"policy":"Full access","futureLimit":17},"permissions":["deployments:read"]}}`)
	}))
	defer server.Close()

	client := NewSessionClient(server.URL, &http.Client{Timeout: time.Second})
	principal, err := client.ValidateBearer(context.Background(), "session-token")
	if err != nil {
		t.Fatalf("ValidateBearer() error = %v", err)
	}
	if principal.ID != "account-123" || principal.Name != "Ada" || principal.Email != "ada@example.test" || principal.Tier != TierAdmin {
		t.Fatalf("principal = %#v", principal)
	}
	if len(principal.Permissions) != 1 || principal.Permissions[0] != "deployments:read" {
		t.Fatalf("permissions = %#v", principal.Permissions)
	}
	var entitlements map[string]any
	if err := json.Unmarshal(principal.Entitlements, &entitlements); err != nil || entitlements["futureLimit"] != float64(17) {
		t.Fatalf("entitlements = %#v, err = %v", entitlements, err)
	}
}

func TestSessionClientKeepsLegacyFlatEntitlementLists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"authenticated":true,"id":"developer-123","roles":["developer"],"entitlements":["trace:read","trace:write"]}`)
	}))
	defer server.Close()

	principal, err := NewSessionClient(server.URL, nil).ValidateBearer(context.Background(), "session-token")
	if err != nil {
		t.Fatalf("ValidateBearer() error = %v", err)
	}
	if principal.ID != "developer-123" || principal.Tier != TierDeveloper {
		t.Fatalf("principal = %#v, want developer-123 with developer tier", principal)
	}
	var entitlements []string
	if err := json.Unmarshal(principal.Entitlements, &entitlements); err != nil || len(entitlements) != 2 || entitlements[0] != "trace:read" {
		t.Fatalf("entitlements = %#v, err = %v", entitlements, err)
	}
}

func TestSessionClientMapsAuthenticationAndProviderErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{}`, want: ErrUnauthenticated},
		{name: "forbidden", status: http.StatusForbidden, body: `{}`, want: ErrUnauthenticated},
		{name: "provider unavailable", status: http.StatusBadGateway, body: `{}`, want: ErrProviderUnavailable},
		{name: "unauthenticated response", status: http.StatusOK, body: `{"authenticated":false}`, want: ErrUnauthenticated},
		{name: "missing authenticated flag", status: http.StatusOK, body: `{"user":{"id":"account-123"}}`, want: ErrUnauthenticated},
		{name: "malformed JSON", status: http.StatusOK, body: `{`, want: ErrMalformedResponse},
		{name: "missing user ID", status: http.StatusOK, body: `{"authenticated":true,"user":{"tier":"free"}}`, want: ErrMalformedResponse},
		{name: "invalid entitlement shape", status: http.StatusOK, body: `{"authenticated":true,"user":{"id":"account-123","entitlements":"bad"}}`, want: ErrMalformedResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()

			_, err := NewSessionClient(server.URL, nil).ValidateBearer(context.Background(), "session-token")
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateBearer() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSessionClientHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := NewSessionClient(server.URL, nil).ValidateBearer(ctx, "session-token")
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("ValidateBearer() error = %v, want ErrProviderUnavailable after deadline", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("session request did not reach the test server")
	}
}

func TestSessionClientRejectsEmptyTokenAndUnavailableConfiguration(t *testing.T) {
	if _, err := NewSessionClient("http://127.0.0.1", nil).ValidateBearer(context.Background(), " "); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty token error = %v, want ErrUnauthenticated", err)
	}
	var client *SessionClient
	if _, err := client.ValidateBearer(context.Background(), "session-token"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil client error = %v, want ErrProviderUnavailable", err)
	}
}
