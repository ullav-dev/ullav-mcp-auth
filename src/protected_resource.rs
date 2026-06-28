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
