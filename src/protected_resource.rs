//! RFC 9728 — Protected Resource Metadata.
//!
//! Each MCP resource server must expose this document so clients can discover
//! the Authorization Server.  The handler also returns the required
//! `WWW-Authenticate` header on 401 responses.

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};

/// Configuration for the protected resource metadata endpoint.
#[derive(Clone)]
pub struct ProtectedResourceConfig {
    /// Canonical URI of this MCP server (e.g. `http://localhost:8085/cunav/mcp`).
    pub resource_uri: String,
    /// URL of the Authorization Server (UUM).
    pub authorization_server: String,
    /// Scopes this server accepts.
    pub scopes_supported: Vec<String>,
    /// JWKS URI published by the AS.
    pub jwks_uri: String,
}

/// `GET /.well-known/oauth-protected-resource`
///
/// Returns the RFC 9728 metadata document.  Register this as an Axum handler.
pub async fn protected_resource_metadata(
    axum::extract::Extension(cfg): axum::extract::Extension<ProtectedResourceConfig>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "resource":              cfg.resource_uri,
        "authorization_servers": [cfg.authorization_server],
        "scopes_supported":      cfg.scopes_supported,
        "bearer_methods_supported": ["header"],
        "jwks_uri":              cfg.jwks_uri,
    }))
}

/// Derives the RFC 9728 `resource_metadata` URL for a resource server's own
/// canonical URI (e.g. `http://localhost:8086/mcp` ->
/// `http://localhost:8086/.well-known/oauth-protected-resource/mcp`) — the
/// path `protected_resource_metadata` is conventionally registered under.
/// Every first-party consumer of this crate was hand-rolling this exact
/// logic in its own `main.rs`; centralizing it here so `mcp_auth_middleware`
/// can build a correct challenge without each caller re-deriving it (and so
/// it can't drift between consumers).
pub fn resource_metadata_url(resource_uri: &str) -> String {
    let path_start = resource_uri
        .find("://")
        .and_then(|i| resource_uri[i + 3..].find('/').map(|j| i + 3 + j))
        .unwrap_or(resource_uri.len());
    let (origin, path) = resource_uri.split_at(path_start);
    format!("{origin}/.well-known/oauth-protected-resource{path}")
}

/// Build a `401 Unauthorized` response with the correct `WWW-Authenticate`
/// header pointing at the protected resource metadata document.
///
/// Pass this to your MCP router's auth middleware error handler.
pub fn unauthorized_response(resource_metadata_url: &str, scope: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            format!(
                r#"Bearer resource_metadata="{resource_metadata_url}", scope="{scope}""#
            ),
        )],
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

/// Build a `403 Forbidden` response with a `WWW-Authenticate` challenge
/// carrying `error="insufficient_scope"` (RFC 6750 §3.1) — for a caller
/// presenting a valid, otherwise-authenticated token that just lacks the
/// scope this resource requires. Distinct from `unauthorized_response`
/// (401: no valid token at all) since a client needs to tell the two apart
/// to know whether re-authenticating would even help.
pub fn insufficient_scope_response(resource_metadata_url: &str, scope: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            format!(
                r#"Bearer resource_metadata="{resource_metadata_url}", scope="{scope}", error="insufficient_scope""#
            ),
        )],
        Json(serde_json::json!({ "error": "insufficient_scope" })),
    )
        .into_response()
}
