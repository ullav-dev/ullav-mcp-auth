//! Confirms `mcp_auth_middleware` actually attaches the RFC 9728
//! `WWW-Authenticate` challenge on a 401 — this is the failure a smoke test
//! caught in lagan-server: the *scope guard* downstream of this middleware
//! had its own header bug, but a request with no `Authorization` header at
//! all never even reaches the scope guard — it's rejected right here. A
//! fix that only touches the scope guard can't close that gap; this test
//! exercises the middleware in isolation, no DB/JWKS server needed, since a
//! missing token never calls out to the validator.

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware, routing::get, Extension, Router,
};
use tower::ServiceExt;
use ullav_mcp_auth::{mcp_auth_middleware, ProtectedResourceConfig, TokenValidator};

fn test_prc() -> ProtectedResourceConfig {
    ProtectedResourceConfig {
        resource_uri: "http://localhost:8086/mcp".to_owned(),
        authorization_server: "http://localhost:8081".to_owned(),
        scopes_supported: vec!["lagan:tools".to_owned()],
        jwks_uri: "http://localhost:8081/oauth2/jwks".to_owned(),
    }
}

fn test_validator() -> TokenValidator {
    // Never actually dialed for the no-token case below — validate() is only
    // called once a Bearer token is present.
    TokenValidator::new(
        "http://localhost:1/jwks",
        "http://localhost:8081",
        "http://localhost:8086/mcp",
    )
}

#[tokio::test]
async fn missing_token_401_carries_www_authenticate_pointing_at_resource_metadata() {
    let app = Router::new()
        .route("/mcp", get(|| async { "ok" }))
        .layer(middleware::from_fn(mcp_auth_middleware))
        .layer(Extension(test_validator()))
        .layer(Extension(test_prc()));

    let resp = app
        .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("401 with no bearer token must carry a WWW-Authenticate challenge")
        .to_str()
        .unwrap();
    assert!(
        challenge.contains(r#"resource_metadata="http://localhost:8086/.well-known/oauth-protected-resource/mcp""#),
        "challenge should point at this service's own metadata doc, got: {challenge}"
    );
    assert!(challenge.contains(r#"scope="lagan:tools""#));
}

#[tokio::test]
async fn missing_prc_extension_falls_back_to_header_less_401_instead_of_500() {
    // A router that forgot to layer Extension<ProtectedResourceConfig> must
    // not turn every unauthenticated request into a 500 — that's a worse
    // regression than the missing header.
    let app = Router::new()
        .route("/mcp", get(|| async { "ok" }))
        .layer(middleware::from_fn(mcp_auth_middleware))
        .layer(Extension(test_validator()));

    let resp = app
        .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
}
