//! Axum middleware that validates RS256 Bearer tokens and injects `McpClaims`.

use crate::{error::AuthError, validator::{McpClaims, TokenValidator}};
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// Extract the Bearer token from the Authorization header.
fn bearer_from_request(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Axum middleware layer.  Validates the Bearer token and inserts the decoded
/// `McpClaims` into request extensions so downstream handlers can retrieve it.
pub async fn mcp_auth_middleware(
    validator: axum::extract::Extension<TokenValidator>,
    mut req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let raw_token = bearer_from_request(&req)
        .ok_or(AuthError::MissingToken)?
        .to_owned();

    let claims = validator.validate(&raw_token).await?;
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
