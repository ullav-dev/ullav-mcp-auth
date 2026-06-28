# ullav-mcp-auth

RS256 JWT validation for Ullav MCP resource servers.

Validates OAuth2 Bearer tokens issued by [ullav-user-management](https://github.com/ullav-dev/ullav-user-management) (the Ullav Authorization Server). Tokens are RS256-signed, audience-bound (RFC 8707), and fetched from the UUM JWKS endpoint with an in-memory per-key cache that refreshes automatically on unknown `kid`.

## Features

- `TokenValidator` — framework-agnostic; use in any async Rust service
- `axum-07` (default) — Axum 0.7 middleware and `/.well-known/oauth-protected-resource` handler (RFC 9728)

## Usage

### `TokenValidator` (no feature flags required)

```rust
use ullav_mcp_auth::TokenValidator;

let validator = TokenValidator::new(
    "https://auth.example.com/oauth2/jwks",  // JWKS URI
    "https://auth.example.com",              // expected issuer
    "https://api.example.com/mcp",           // expected audience (this server's canonical URI)
);

// Validate an MCP Bearer token — returns typed McpClaims on success.
let claims = validator.validate(&raw_token).await?;
println!("user: {}, scope: {}", claims.username, claims.scope);

// Validate a general UUM API token (no audience check).
let generic_claims = validator.validate_as::<serde_json::Value>(&raw_token).await?;
```

`TokenValidator` is `Clone` (cheaply ref-counted) — create once, clone into handlers.

### Axum 0.7 middleware

```toml
[dependencies]
ullav-mcp-auth = { git = "https://github.com/ullav-dev/ullav-mcp-auth" }
```

```rust
use ullav_mcp_auth::{mcp_auth_middleware, ProtectedResourceConfig};

// Serve /.well-known/oauth-protected-resource (RFC 9728)
let config = ProtectedResourceConfig {
    resource_uri: "https://api.example.com/mcp".into(),
    authorization_server: "https://auth.example.com".into(),
    jwks_uri: "https://auth.example.com/oauth2/jwks".into(),
};

let app = Router::new()
    .route("/.well-known/oauth-protected-resource",
        get(protected_resource_metadata).with_state(config))
    .route("/mcp", post(mcp_handler))
    .layer(from_fn_with_state(validator, mcp_auth_middleware));
```

### Without the Axum middleware (Axum 0.8+ or other frameworks)

```toml
[dependencies]
ullav-mcp-auth = { git = "https://github.com/ullav-dev/ullav-mcp-auth", default-features = false }
```

Use `TokenValidator` directly in your own middleware. The `clann-server` codebase has a reference implementation of a hand-rolled Axum 0.8 middleware using `TokenValidator`.

## Claims

Tokens issued by UUM carry:

| Claim | Description |
|---|---|
| `iss` | Issuer — the UUM public URL |
| `sub` | User UUID |
| `aud` | Audience — the MCP server's canonical URI |
| `scope` | Space-separated OAuth2 scopes (e.g. `mcp:tools`) |
| `client_id` | OAuth2 client that obtained the token |
| `username` | Human-readable username |
| `exp` / `iat` | Standard expiry / issued-at |

## Error handling

`AuthError` variants:

- `InvalidToken(String)` — JWT decode or validation failed (bad signature, expired, wrong issuer/audience)
- `KeyNotFound(Option<String>)` — token's `kid` not found in JWKS after a fresh fetch
- `JwksFetch(String)` — network or parse error fetching the JWKS endpoint
