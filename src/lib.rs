pub mod error;
pub mod validator;

#[cfg(feature = "axum-07")]
pub mod middleware;
#[cfg(feature = "axum-07")]
pub mod protected_resource;

pub use error::AuthError;
pub use validator::{McpClaims, TokenValidator};

#[cfg(feature = "axum-07")]
pub use middleware::{mcp_auth_middleware, ClaimsExtractor};
#[cfg(feature = "axum-07")]
pub use protected_resource::{protected_resource_metadata, unauthorized_response, ProtectedResourceConfig};
