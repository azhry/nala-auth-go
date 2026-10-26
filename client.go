package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrUnauthenticated     = errors.New("nala auth: session rejected")
	ErrProviderUnavailable = errors.New("nala auth: session provider unavailable")
	ErrMalformedResponse   = errors.New("nala auth: session response invalid")
)

const defaultSessionTimeout = 5 * time.Second

type SessionClient struct {
	baseURL string
	client  *http.Client
}

func NewSessionClient(baseURL string, client *http.Client) *SessionClient {
	if client == nil {
		client = &http.Client{Timeout: defaultSessionTimeout}
	}
	return &SessionClient{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), client: client}
}

// ValidateBearer asks Nala Labs to validate a session and return its current
// principal. The bearer token is sent only to /api/auth/session; no signing
// secret is needed or transmitted.
func (c *SessionClient) ValidateBearer(ctx context.Context, token string) (Principal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Principal{}, ErrUnauthenticated
	}
	if c == nil || c.client == nil || c.baseURL == "" {
		return Principal{}, ErrProviderUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/auth/session", nil)
	if err != nil {
		return Principal{}, ErrProviderUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := c.client.Do(request)
	if err != nil {
		return Principal{}, ErrProviderUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Principal{}, ErrProviderUnavailable
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return Principal{}, ErrUnauthenticated
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Principal{}, ErrProviderUnavailable
	}
	principal, err := decodeSession(body)
	if err != nil {
		return Principal{}, err
	}
	return principal, nil
}

type sessionResponse struct {
	Authenticated *bool     `json:"authenticated"`
	User          Principal `json:"user"`

	ID           string          `json:"id"`
	UserID       string          `json:"user_id"`
	Subject      string          `json:"sub"`
	Name         string          `json:"name"`
	DisplayName  string          `json:"display_name"`
	Email        string          `json:"email"`
	Roles        []string        `json:"roles"`
	Groups       []string        `json:"groups"`
	Tags         []string        `json:"tags"`
	Admin        bool            `json:"admin"`
	Tier         Tier            `json:"tier"`
	Tag          string          `json:"tag"`
	IsAdmin      bool            `json:"isAdmin"`
	Entitlements json.RawMessage `json:"entitlements"`
	Permissions  []string        `json:"permissions"`
}

func decodeSession(body []byte) (Principal, error) {
	var response sessionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return Principal{}, ErrMalformedResponse
	}
	if response.Authenticated == nil || !*response.Authenticated {
		return Principal{}, ErrUnauthenticated
	}
	principal := response.User
	if principal.ID == "" && principal.UserID == "" && principal.Subject == "" {
		principal = Principal{
			ID: response.ID, UserID: response.UserID, Subject: response.Subject,
			Name: response.Name, DisplayName: response.DisplayName, Email: response.Email,
			Roles: response.Roles, Groups: response.Groups, Tags: response.Tags,
			Admin: response.Admin, Tier: response.Tier, Tag: response.Tag,
			IsAdmin: response.IsAdmin, Entitlements: response.Entitlements,
			Permissions: response.Permissions,
		}
	}
	principal.ID = firstNonEmpty(principal.ID, principal.UserID, principal.Subject)
	if principal.ID == "" || !validEntitlements(principal.Entitlements, true) {
		return Principal{}, ErrMalformedResponse
	}
	principal.Name = firstNonEmpty(principal.Name, principal.DisplayName)
	principal.Tier = remoteTier(principal)
	return principal, nil
}

func remoteTier(principal Principal) Tier {
	explicit := NormalizeTier(string(principal.Tier))
	if explicit == TierAdmin || explicit == TierDeveloper {
		return explicit
	}
	if principal.Admin || principal.IsAdmin || hasLabel(principal, "admin") {
		return TierAdmin
	}
	if hasLabel(principal, "developer") {
		return TierDeveloper
	}
	return TierFree
}

func hasLabel(principal Principal, wanted string) bool {
	if strings.EqualFold(strings.TrimSpace(principal.Tag), wanted) {
		return true
	}
	for _, values := range [][]string{principal.Roles, principal.Groups, principal.Tags} {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), wanted) {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
