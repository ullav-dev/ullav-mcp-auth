use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing or malformed Authorization header")]
    MissingToken,

    #[error("token validation failed: {0}")]
    InvalidToken(String),

    #[error("token audience does not match this resource server")]
    AudienceMismatch,

    #[error("failed to fetch JWKS: {0}")]
    JwksFetch(String),

    #[error("no matching key in JWKS for kid {0:?}")]
    KeyNotFound(Option<String>),
}

#[cfg(feature = "axum-07")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let status = match &self {
            AuthError::MissingToken | AuthError::InvalidToken(_) | AuthError::AudienceMismatch => {
                StatusCode::UNAUTHORIZED
            }
            AuthError::JwksFetch(_) | AuthError::KeyNotFound(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let body = serde_json::json!({ "error": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}
