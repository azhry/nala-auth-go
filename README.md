# Nala Labs Auth Go SDK

Module: `github.com/azhry/nala-auth-go`.

Install with `go get github.com/azhry/nala-auth-go@latest`.

This module shares Nala Labs session validation between Go services. It does not start a login flow or issue tokens.

`VerifyLocal` validates the existing HS256 session JWT using the secret already configured for the consuming service. It requires a `sub` matching `user.id` and a future `exp`, and returns the user, normalized tier, permissions when present, and the original entitlement JSON.

`NewSessionClient` creates a client for Nala Labs `GET /api/auth/session`. `ValidateBearer` accepts a context and bearer token, and returns the current principal without sending a signing secret.

For local verification in Nala Labs and nala-svc:

```go
import authsdk "github.com/azhry/nala-auth-go"

claims, err := authsdk.VerifyLocal(token, []byte(sessionSecret))
if err != nil {
	return authsdk.Principal{}, err
}
return claims.User, nil
```

For remote session validation in nala-trace:

```go
import authsdk "github.com/azhry/nala-auth-go"

sessions := authsdk.NewSessionClient(nalaLabsAuthURL, nil)
return sessions.ValidateBearer(ctx, token)
```

The SDK uses only the Go standard library. Callers map `TierFree`, `TierDeveloper`, and `TierAdmin` into their existing service types and keep API-key and other authentication paths in their owning service.
