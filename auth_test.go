package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyLocalPreservesSessionPrincipal(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	token := signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, map[string]any{
		"sub": "account-123",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"user": map[string]any{
			"id":           "account-123",
			"name":         "Ada",
			"email":        "ada@example.test",
			"tier":         "developer",
			"entitlements": map[string]any{"policy": "Developer resources", "futureLimit": 17},
			"permissions":  []string{"deployments:read", "deployments:write"},
		},
	})

	claims, err := VerifyLocal(token, []byte("test secret"), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("VerifyLocal() error = %v", err)
	}
	if claims.Subject != "account-123" || claims.User.ID != "account-123" || claims.User.Tier != TierDeveloper {
		t.Fatalf("principal = %#v, want account-123 with developer tier", claims.User)
	}
	if claims.User.Name != "Ada" || claims.User.Email != "ada@example.test" {
		t.Fatalf("user fields = %#v", claims.User)
	}
	if got, want := claims.User.Permissions, []string{"deployments:read", "deployments:write"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("permissions = %#v, want %#v", got, want)
	}
	var entitlements map[string]any
	if err := json.Unmarshal(claims.User.Entitlements, &entitlements); err != nil {
		t.Fatalf("decode entitlements: %v", err)
	}
	if entitlements["futureLimit"] != float64(17) || entitlements["policy"] != "Developer resources" {
		t.Fatalf("entitlements = %#v, want unknown and existing fields preserved", entitlements)
	}
}

func TestVerifyLocalRejectsInvalidSessionTokens(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	validClaims := map[string]any{
		"sub":  "account-123",
		"exp":  now.Add(time.Hour).Unix(),
		"user": map[string]any{"id": "account-123"},
	}
	valid := signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, validClaims)
	parts := strings.Split(valid, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	badSignature := strings.Join(parts, ".")
	wrongAlgorithm := signedToken(t, "test secret", map[string]string{"alg": "none", "typ": "JWT"}, validClaims)
	expiredClaims := map[string]any{"sub": "account-123", "exp": now.Add(-time.Second).Unix(), "user": map[string]string{"id": "account-123"}}
	mismatchedClaims := map[string]any{"sub": "account-123", "exp": now.Add(time.Hour).Unix(), "user": map[string]string{"id": "other"}}
	invalidEntitlements := map[string]any{"sub": "account-123", "exp": now.Add(time.Hour).Unix(), "user": map[string]any{"id": "account-123", "entitlements": "unexpected"}}

	for _, test := range []struct {
		name  string
		token string
	}{
		{name: "malformed token", token: "not-a-jwt"},
		{name: "wrong algorithm", token: wrongAlgorithm},
		{name: "wrong signature", token: badSignature},
		{name: "missing subject", token: signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, map[string]any{"exp": now.Add(time.Hour).Unix(), "user": map[string]string{"id": "account-123"}})},
		{name: "subject mismatch", token: signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, mismatchedClaims)},
		{name: "expired", token: signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, expiredClaims)},
		{name: "invalid entitlements", token: signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, invalidEntitlements)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := VerifyLocal(test.token, []byte("test secret"), WithClock(func() time.Time { return now }))
			if err != ErrInvalidToken {
				t.Fatalf("VerifyLocal() error = %v, want ErrInvalidToken", err)
			}
		})
	}
	if _, err := VerifyLocal(valid, nil); err != ErrInvalidSecret {
		t.Fatalf("VerifyLocal() with empty secret error = %v, want ErrInvalidSecret", err)
	}
}

func TestVerifyLocalUsesExistingAdminClaims(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	token := signedToken(t, "test secret", map[string]string{"alg": "HS256", "typ": "JWT"}, map[string]any{
		"sub":  "admin-123",
		"exp":  now.Add(time.Hour).Unix(),
		"user": map[string]any{"id": "admin-123", "tag": "admin", "isAdmin": true},
	})
	claims, err := VerifyLocal(token, []byte("test secret"), WithClock(func() time.Time { return now }))
	if err != nil || claims.User.Tier != TierAdmin {
		t.Fatalf("VerifyLocal() = %#v, %v; want admin", claims.User, err)
	}
}

func signedToken(t *testing.T, secret string, header map[string]string, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	input := encodedHeader + "." + encodedClaims
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestNormalizeTier(t *testing.T) {
	for input, want := range map[string]Tier{
		"free":      TierFree,
		"developer": TierDeveloper,
		"ADMIN":     TierAdmin,
		"unknown":   TierFree,
		" ":         TierFree,
	} {
		if got := NormalizeTier(input); got != want {
			t.Errorf("NormalizeTier(%q) = %q, want %q", input, got, want)
		}
	}
}
