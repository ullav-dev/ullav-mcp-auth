//! Axum middleware that validates RS256 Bearer tokens and injects `McpClaims`.

use crate::{
    error::AuthError,
    protected_resource::{resource_metadata_url, unauthorized_response, ProtectedResourceConfig},
    validator::{McpClaims, TokenValidator},
};
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Extract the Bearer token from the Authorization header.
fn bearer_from_request(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Turns an `AuthError` into a response, attaching the RFC 9728
/// `WWW-Authenticate` challenge for the two cases a client can actually act
/// on (no token / invalid token / wrong audience — all "come back with a
/// fresh token"). `JwksFetch`/`KeyNotFound` are this server's own transient
/// failure to validate anything, not a challenge to the client, so those
/// stay header-less 503s, same as before.
///
/// `prc` is `None` when a caller's router doesn't layer
/// `Extension<ProtectedResourceConfig>` above this middleware — falls back
/// to the old header-less response rather than hard-erroring, since a
/// missing header is the bug this exists to fix, not a worse one, but logs
/// so the gap gets noticed.
fn challenge_response(prc: Option<&ProtectedResourceConfig>, err: AuthError) -> Response {
    match (&err, prc) {
        (AuthError::MissingToken | AuthError::InvalidToken(_) | AuthError::AudienceMismatch, Some(prc)) => {
            let metadata_url = resource_metadata_url(&prc.resource_uri);
            unauthorized_response(&metadata_url, &prc.scopes_supported.join(" "))
        }
        (AuthError::MissingToken | AuthError::InvalidToken(_) | AuthError::AudienceMismatch, None) => {
            tracing::warn!(
                "mcp_auth_middleware: no Extension<ProtectedResourceConfig> layered on this \
                 router — falling back to a WWW-Authenticate-less 401. Layer \
                 Extension(protected_resource_config) alongside Extension(token_validator) to fix."
            );
            err.into_response()
        }
        (AuthError::JwksFetch(_) | AuthError::KeyNotFound(_), _) => err.into_response(),
    }
}

/// Axum middleware layer.  Validates the Bearer token and inserts the decoded
/// `McpClaims` into request extensions so downstream handlers can retrieve it.
pub async fn mcp_auth_middleware(
    validator: axum::extract::Extension<TokenValidator>,
    prc: Option<axum::extract::Extension<ProtectedResourceConfig>>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let prc = prc.map(|axum::extract::Extension(prc)| prc);
    let raw_token = match bearer_from_request(&req) {
        Some(t) => t.to_owned(),
        None => return Err(challenge_response(prc.as_ref(), AuthError::MissingToken)),
    };

    let claims = match validator.validate(&raw_token).await {
        Ok(c) => c,
        Err(e) => return Err(challenge_response(prc.as_ref(), e)),
    };
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Convenience extractor: pull `McpClaims` from request extensions.
///
/// Use this in handlers:
/// ```rust,ignore
/// use ullav_mcp_auth::middleware::ClaimsExtractor;
/// async fn my_handler(ClaimsExtractor(claims): ClaimsExtractor) { /* use claims */ }
/// ```
pub struct ClaimsExtractor(pub McpClaims);

#[axum::async_trait]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClaimsExtractor {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<McpClaims>()
            .cloned()
            .map(ClaimsExtractor)
            .ok_or(AuthError::MissingToken)
    }
}
