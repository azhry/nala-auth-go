package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidSecret = errors.New("nala auth: session secret is required")
	ErrInvalidToken  = errors.New("nala auth: invalid session token")
)

type Tier string

const (
	TierFree      Tier = "free"
	TierDeveloper Tier = "developer"
	TierAdmin     Tier = "admin"
)

// Principal contains the Nala Labs identity fields shared by its services.
// Entitlements remains raw JSON so unknown policy fields are not discarded.
type Principal struct {
	ID           string          `json:"id"`
	UserID       string          `json:"user_id,omitempty"`
	Subject      string          `json:"sub,omitempty"`
	Name         string          `json:"name,omitempty"`
	DisplayName  string          `json:"display_name,omitempty"`
	Email        string          `json:"email,omitempty"`
	Tier         Tier            `json:"tier,omitempty"`
	Tag          string          `json:"tag,omitempty"`
	IsAdmin      bool            `json:"isAdmin,omitempty"`
	Roles        []string        `json:"roles,omitempty"`
	Groups       []string        `json:"groups,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Admin        bool            `json:"admin,omitempty"`
	Entitlements json.RawMessage `json:"entitlements,omitempty"`
	Permissions  []string        `json:"permissions,omitempty"`
}

type Claims struct {
	Subject   string    `json:"sub"`
	User      Principal `json:"user"`
	Tier      Tier      `json:"tier,omitempty"`
	IssuedAt  int64     `json:"iat,omitempty"`
	ExpiresAt int64     `json:"exp"`
}

type VerifierOption func(*Verifier)

// WithClock supplies the clock used for expiration checks. It is useful when
// a service already has an injectable clock for its session lifecycle.
func WithClock(now func() time.Time) VerifierOption {
	return func(verifier *Verifier) {
		if now != nil {
			verifier.now = now
		}
	}
}

type Verifier struct {
	secret []byte
	now    func() time.Time
}

func NewVerifier(secret []byte, options ...VerifierOption) (*Verifier, error) {
	if len(secret) == 0 || strings.TrimSpace(string(secret)) == "" {
		return nil, ErrInvalidSecret
	}
	verifier := &Verifier{secret: append([]byte(nil), secret...), now: time.Now}
	for _, option := range options {
		if option != nil {
			option(verifier)
		}
	}
	return verifier, nil
}

// VerifyLocal validates a Nala Labs HS256 session token without making a
// network request. The secret must come from the consuming service's existing
// configuration; this package does not load or log it.
func VerifyLocal(token string, secret []byte, options ...VerifierOption) (Claims, error) {
	verifier, err := NewVerifier(secret, options...)
	if err != nil {
		return Claims{}, err
	}
	return verifier.Verify(token)
}

func (v *Verifier) Verify(token string) (Claims, error) {
	if v == nil || len(v.secret) == 0 {
		return Claims{}, ErrInvalidSecret
	}
	if v.now == nil {
		return Claims{}, ErrInvalidSecret
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "HS256" || header.Type != "JWT" {
		return Claims{}, ErrInvalidToken
	}

	mac := hmac.New(sha256.New, v.secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expected, actual) {
		return Claims{}, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Subject == "" || claims.User.ID == "" || claims.Subject != claims.User.ID {
		return Claims{}, ErrInvalidToken
	}
	if claims.ExpiresAt <= v.now().Unix() || !validEntitlements(claims.User.Entitlements, false) {
		return Claims{}, ErrInvalidToken
	}
	claims.User.Tier = localTier(claims)
	return claims, nil
}

func localTier(claims Claims) Tier {
	value := strings.TrimSpace(string(claims.Tier))
	if value == "" {
		value = strings.TrimSpace(string(claims.User.Tier))
	}
	if value == "" && len(claims.User.Entitlements) > 0 {
		var entitlements struct {
			Policy string `json:"policy"`
		}
		_ = json.Unmarshal(claims.User.Entitlements, &entitlements)
		value = strings.TrimSpace(entitlements.Policy)
	}
	if value == "" {
		value = strings.TrimSpace(claims.User.Tag)
	}
	if claims.User.IsAdmin || strings.EqualFold(strings.TrimSpace(claims.User.Tag), "admin") {
		return TierAdmin
	}
	return NormalizeTier(value)
}

func NormalizeTier(value string) Tier {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(TierAdmin):
		return TierAdmin
	case string(TierDeveloper):
		return TierDeveloper
	default:
		return TierFree
	}
}

func validEntitlements(raw json.RawMessage, allowList bool) bool {
	if len(raw) == 0 {
		return true
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	switch value.(type) {
	case nil, map[string]any:
		return true
	case []any:
		if !allowList {
			return false
		}
		var list []string
		return json.Unmarshal(raw, &list) == nil
	default:
		return false
	}
}
