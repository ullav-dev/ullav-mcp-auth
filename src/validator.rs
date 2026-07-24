//! RS256 JWT validator with in-memory JWKS cache.
//!
//! The cache is refreshed automatically on every request where the token's `kid`
//! does not match any cached key, so key rotation propagates without a restart.

use crate::error::AuthError;
use dashmap::DashMap;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// A user's subscription to a product, as embedded in UUM-issued tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionClaim {
    /// Plan name: "individual", "family", "professional", "enterprise", etc.
    pub tier: String,
    /// Subscription status: "active", "trialing", "past_due", "cancelled".
    pub status: String,
}

/// A user's role within a team, as embedded in UUM-issued tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamClaim {
    /// Positional role: `"owner"`, `"leader"`, or `"member"`.
    pub role: String,
    /// Product slugs this team has enabled (from `team_product_access`).
    /// Defaults to empty so tokens minted before this field was added still decode.
    #[serde(default)]
    pub products: Vec<String>,
    /// The team's organization, if it has one assigned (most teams don't, yet —
    /// organizations are a new, optional UUM concept). Defaults to `None` so
    /// tokens minted before organizations existed still decode.
    #[serde(default)]
    pub organization_id: Option<String>,
}

/// Claims present in OAuth2 access tokens issued by UUM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpClaims {
    pub iss: String,
    pub sub: String,
    /// Audience — the canonical URI of this resource server.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub scope: String,
    pub client_id: String,
    pub username: String,
    /// Roles assigned to the user. Defaults to empty so tokens minted before this
    /// field was added still decode.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Active subscriptions keyed by product slug. Defaults to an empty map so
    /// tokens minted before this field was added still decode.
    #[serde(default)]
    pub subscriptions: HashMap<String, SubscriptionClaim>,
    /// Active team memberships keyed by team UUID string. Defaults to an empty map
    /// so tokens minted before this field was added still decode.
    #[serde(default)]
    pub teams: HashMap<String, TeamClaim>,
}

/// Cached JWKS key entry.
#[derive(Clone)]
struct CachedKey {
    decoding_key: Arc<DecodingKey>,
}

/// Thread-safe RS256 token validator.
///
/// Create once and share via `Arc` or `Clone` (cheaply ref-counted).
#[derive(Clone)]
pub struct TokenValidator {
    http_client: Client,
    jwks_uri: String,
    issuer: String,
    /// Expected audience — the canonical URI of this MCP server.
    audience: String,
    /// kid → DecodingKey cache.
    cache: Arc<DashMap<String, CachedKey>>,
}

impl TokenValidator {
    pub fn new(jwks_uri: impl Into<String>, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            http_client: Client::new(),
            jwks_uri: jwks_uri.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Validate a raw Bearer token string, returning the decoded claims on success.
    pub async fn validate(&self, raw_token: &str) -> Result<McpClaims, AuthError> {
        let header = decode_header(raw_token)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let kid = header.kid.clone();

        // Try cached key first.
        if let Some(entry) = kid.as_ref().and_then(|k| self.cache.get(k.as_str())) {
            if let Ok(claims) = self.decode_with_key(raw_token, &entry.decoding_key) {
                return Ok(claims);
            }
        }

        // Cache miss (or validation failed with cached key) — refresh JWKS.
        debug!("Refreshing JWKS from {}", self.jwks_uri);
        let keys = self.fetch_jwks().await?;

        let target_kid = kid.as_deref().unwrap_or("");
        let key = keys
            .into_iter()
            .find(|(k, _)| k == target_kid)
            .map(|(_, v)| v)
            .ok_or_else(|| AuthError::KeyNotFound(kid.clone()))?;

        let key = Arc::new(key);
        if let Some(k) = &kid {
            self.cache.insert(k.clone(), CachedKey { decoding_key: key.clone() });
        }

        self.decode_with_key(raw_token, &key)
    }

    /// Validate a token and decode into an arbitrary claims type.
    ///
    /// Audience validation is skipped — use this for service-API tokens that do not
    /// carry an `aud` claim (i.e. UUM `/auth/login` RS256 tokens for general API access).
    /// The issuer and expiry are still verified.
    pub async fn validate_as<C: DeserializeOwned>(&self, raw_token: &str) -> Result<C, AuthError> {
        let header = decode_header(raw_token)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let kid = header.kid.clone();

        if let Some(entry) = kid.as_ref().and_then(|k| self.cache.get(k.as_str())) {
            if let Ok(claims) = self.decode_with_key_as::<C>(raw_token, &entry.decoding_key) {
                return Ok(claims);
            }
        }

        debug!("Refreshing JWKS from {} (validate_as)", self.jwks_uri);
        let keys = self.fetch_jwks().await?;

        let target_kid = kid.as_deref().unwrap_or("");
        let key = keys
            .into_iter()
            .find(|(k, _)| k == target_kid)
            .map(|(_, v)| v)
            .ok_or_else(|| AuthError::KeyNotFound(kid.clone()))?;

        let key = Arc::new(key);
        if let Some(k) = &kid {
            self.cache.insert(k.clone(), CachedKey { decoding_key: key.clone() });
        }

        self.decode_with_key_as::<C>(raw_token, &key)
    }

    fn decode_with_key(&self, raw_token: &str, key: &DecodingKey) -> Result<McpClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        decode::<McpClaims>(raw_token, key, &validation)
            .map(|d| d.claims)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    fn decode_with_key_as<C: DeserializeOwned>(&self, raw_token: &str, key: &DecodingKey) -> Result<C, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        // No audience check — general API tokens may not carry 'aud'.
        validation.validate_aud = false;

        decode::<C>(raw_token, key, &validation)
            .map(|d| d.claims)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    async fn fetch_jwks(&self) -> Result<Vec<(String, DecodingKey)>, AuthError> {
        let resp: serde_json::Value = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;

        let keys = resp["keys"]
            .as_array()
            .ok_or_else(|| AuthError::JwksFetch("JWKS response missing 'keys' array".into()))?;

        let mut out = Vec::new();
        for jwk in keys {
            if jwk["alg"] != "RS256" {
                continue;
            }
            let kid = jwk["kid"].as_str().unwrap_or("").to_owned();
            let n = jwk["n"].as_str()
                .ok_or_else(|| AuthError::JwksFetch("JWK missing 'n'".into()))?;
            let e = jwk["e"].as_str()
                .ok_or_else(|| AuthError::JwksFetch("JWK missing 'e'".into()))?;
            match DecodingKey::from_rsa_components(n, e) {
                Ok(k) => out.push((kid, k)),
                Err(err) => warn!("Skipping JWK with kid={kid:?}: {err}"),
            }
        }
        Ok(out)
    }
}

// Pre-generated RSA-2048 PKCS#8 key for tests only (no security value).
// Generated with: openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt
// kid = SHA-256(n_bytes || e_bytes)[..16 hex chars] = "87876bda381be12e"
// n and e extracted from the public key with Python + base64url encoding.
#[cfg(test)]
const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmlldRsE7C5HFB
PrcDQWqhr/j+aI5CrtYvIaj2jxPy1tFj/MFQSwKHISLcyALo9mY+17/v+WrkXNYo
az2B7KU101Lsy+WMSVl56zqPFuNvKOWYxFmvZbqvebGWI+zdQ1k2lKy9JykOGIA9
fQOb5+Cu6w7SJZNSh1FhrJnxODecjcQvD/cCrps2+akQPy8TR76oTwDA0tynV+4w
J/alqA5E9OAnDXsgBB5YW2A2uyGrIum8OTizlboWWK/8SO+1+VRIPTuGkDbll3lo
6MzaGXHiZdAsjmCScBv0DEyInFJC+/hOJ6Ac2N8TZ4eiuTYS/BED6Cug9dC8wLDX
6i0WYWVrAgMBAAECggEAB2yKdlYtzGWzM73Vw3a2Mn/N0ENcmQAtr2qymvpZYJMj
lcR9NlTWx1WPYNjRDbdywGOLvD1t/sCxvUS6OFYRhB/ngYISDXnKBl2YqH5+ou+R
poiUQ/V7/Qymq2hCdWyQ8evCSakQcqkI3gn6OofPmDwFgbwG9WtDvInypQYPrxGt
PxeicsMyqjsnB6RJ8vLX8qzD1ISzTcwuBb01hGuMoL7jecalnaZNOPsFwcgnJeX9
UPRbTgLWuAhUpcWJ2BcKi1axiDR+shj7WpFiZkT53qFYLsuAX2n7XtmyTnIzC4bt
ujr/I6T5HECu4rcyj3zGOOjxE31yxSiG6o3Krq0HIQKBgQDSIxLoPoOkAsXqSdWf
YRPj3/l+H+1MAOgywxQ2kCWZ1M2eHch7cDaJC2yuLYwSOLySthsM1BN1wQdukq4D
iM9ojqa6/fd/4mz6kLbcbCWNNIFYSOH/zauXjO6QkuGx06EY3bHxhhcNORq8K0RO
qPHpNBFLNVT8Y9AdeKJXGcegwwKBgQDK8gZjk+6nQfM9ge3GdRHEccn700dmPeJ0
Qqmy+AYS08R8HrRAlMFaOmMmA/24Bl9HoaPJnPCVxcUDK9LvqBcMpgVVcoGN8I3D
xyBEBUsfjpULIZUxtROChLUJI44z8l3cH7Lb/pWxuS+YRcfEwtwEmo/wVclNMcrD
IpBcdg1eOQKBgAq0xMLWZIiXp5O/PUYIgSXsBF8bq1Bi/3GOpNn+0BudTviOVeeM
GQs0bM4W/frzrw/efVRS/cbTFdjZWkpNzxtpoS8Hv3NhiuHdO6PRUrx1/10LIZCR
3vsyr/jnst4HhT6qFOXUShpfXXBW1/0V+HVENNlbF0BgqXrG6aZ8ZsJXAoGBAJf3
4gbg+J2wieduCtJISdSzbI+xJ08NWiy62n5UsZ+ZihFzoICXo63f+Oy3ol8SDnkC
Nja72YAdxyhXwa2KTjA/hdD1XMQf9Ng8nRGycQ2hZEQgkqrVMFXU8Ad2435MqDI0
XmfUXN3nkRdScYQKclzULKLIamPuvCmhET7be6kpAoGAHyCJt5Rk4bgSye5w9yL6
QTXa5JJsPIvCAkiD3vQWWT/H5P+xdkbg4i0thWs4J00IeiRecvXYrNl9FdJwxA9/
2v54uCFCedfo4O6RM/Ej072W8FJtUyr7zeC+wJSBe1d9C6nG41a0IGcMeW8ksiGD
lpBVpUpFyamQ/8kYl9RLMRM=
-----END PRIVATE KEY-----";

#[cfg(test)]
const TEST_KEY_KID: &str = "87876bda381be12e";
#[cfg(test)]
const TEST_KEY_N: &str = "ppZXUbBOwuRxQT63A0Fqoa_4_miOQq7WLyGo9o8T8tbRY_zBUEsChyEi3MgC6PZmPte_7_lq5FzWKGs9geylNdNS7MvljElZees6jxbjbyjlmMRZr2W6r3mxliPs3UNZNpSsvScpDhiAPX0Dm-fgrusO0iWTUodRYayZ8Tg3nI3ELw_3Aq6bNvmpED8vE0e-qE8AwNLcp1fuMCf2pagORPTgJw17IAQeWFtgNrshqyLpvDk4s5W6Fliv_EjvtflUSD07hpA25Zd5aOjM2hlx4mXQLI5gknAb9AxMiJxSQvv4TiegHNjfE2eHork2EvwRA-groPXQvMCw1-otFmFlaw";
#[cfg(test)]
const TEST_KEY_E: &str = "AQAB";

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn test_jwks() -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": TEST_KEY_KID,
                "n": TEST_KEY_N,
                "e": TEST_KEY_E
            }]
        })
    }

    fn mint_test_token(issuer: &str, audience: &str, sub: &str, scope: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = McpClaims {
            iss: issuer.into(),
            sub: sub.into(),
            aud: audience.into(),
            iat: now,
            exp: now + 3600,
            scope: scope.into(),
            client_id: "claude-desktop".into(),
            username: "testuser".into(),
            roles: vec![],
            subscriptions: HashMap::new(),
            teams: HashMap::new(),
        };
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes())
            .expect("test key should load");
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KEY_KID.into());
        encode(&header, &claims, &key).expect("token signing should succeed")
    }

    /// Mint a token whose JSON payload has none of the plan-data fields at all —
    /// simulating a token issued before `roles`/`subscriptions`/`teams` were added.
    fn mint_legacy_test_token(issuer: &str, audience: &str, sub: &str, scope: &str) -> String {
        #[derive(Serialize)]
        struct LegacyClaims {
            iss: String,
            sub: String,
            aud: String,
            iat: i64,
            exp: i64,
            scope: String,
            client_id: String,
            username: String,
        }
        let now = chrono::Utc::now().timestamp();
        let claims = LegacyClaims {
            iss: issuer.into(),
            sub: sub.into(),
            aud: audience.into(),
            iat: now,
            exp: now + 3600,
            scope: scope.into(),
            client_id: "claude-desktop".into(),
            username: "testuser".into(),
        };
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes())
            .expect("test key should load");
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KEY_KID.into());
        encode(&header, &claims, &key).expect("token signing should succeed")
    }

    #[tokio::test]
    async fn validator_rejects_bad_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "keys": [] }),
            ))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            "http://localhost:8081",
            "http://localhost:8085/cunav/mcp",
        );
        let err = v.validate("not.a.jwt").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn validator_rejects_empty_jwks() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "keys": [] }),
            ))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            "http://localhost:8081",
            "http://localhost:8085/cunav/mcp",
        );
        // A structurally valid JWT with a kid that won't match anything.
        // Use a fake but well-formed token header (base64url-encoded).
        let fake = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2Uta2lkIn0.eyJzdWIiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.sig";
        let err = v.validate(fake).await.unwrap_err();
        assert!(matches!(err, AuthError::KeyNotFound(_)));
    }

    #[tokio::test]
    async fn validator_accepts_valid_rs256_token() {
        let issuer = "http://localhost:8081";
        let audience = "http://localhost:8085/cunav/mcp";
        let sub = "550e8400-e29b-41d4-a716-446655440000";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            issuer,
            audience,
        );

        let token = mint_test_token(issuer, audience, sub, "cunav:read");
        let claims = v.validate(&token).await.expect("valid token should be accepted");

        assert_eq!(claims.iss, issuer);
        assert_eq!(claims.sub, sub);
        assert_eq!(claims.aud, audience);
        assert_eq!(claims.scope, "cunav:read");
        assert_eq!(claims.client_id, "claude-desktop");
        assert_eq!(claims.username, "testuser");
    }

    #[tokio::test]
    async fn validator_rejects_wrong_audience() {
        let issuer = "http://localhost:8081";
        let audience = "http://localhost:8085/cunav/mcp";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            issuer,
            audience,
        );

        let token = mint_test_token(issuer, "http://wrong.example.com/api", "user1", "read");
        let err = v.validate(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn validator_rejects_wrong_issuer() {
        let audience = "http://localhost:8085/cunav/mcp";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            "http://localhost:8081",
            audience,
        );

        // Token claims issuer "http://evil.example.com" but validator expects "http://localhost:8081"
        let token = mint_test_token("http://evil.example.com", audience, "user1", "read");
        let err = v.validate(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn validator_decodes_legacy_token_missing_plan_fields() {
        let issuer = "http://localhost:8081";
        let audience = "http://localhost:8085/cunav/mcp";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            issuer,
            audience,
        );

        let token = mint_legacy_test_token(issuer, audience, "user1", "dam:tools");
        let claims = v.validate(&token).await.expect("legacy token should still decode");

        assert!(claims.roles.is_empty());
        assert!(claims.subscriptions.is_empty());
        assert!(claims.teams.is_empty());
    }

    #[tokio::test]
    async fn validator_decodes_plan_data_fields() {
        let issuer = "http://localhost:8081";
        let audience = "http://localhost:8085/cunav/mcp";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            issuer,
            audience,
        );

        let now = chrono::Utc::now().timestamp();
        let mut subscriptions = HashMap::new();
        subscriptions.insert(
            "comad".to_string(),
            SubscriptionClaim { tier: "team".into(), status: "active".into() },
        );
        let mut teams = HashMap::new();
        teams.insert(
            "team-1".to_string(),
            TeamClaim { role: "owner".into(), products: vec!["tack".into()], organization_id: Some("org-1".into()) },
        );

        let claims = McpClaims {
            iss: issuer.into(),
            sub: "user1".into(),
            aud: audience.into(),
            iat: now,
            exp: now + 3600,
            scope: "dam:tools".into(),
            client_id: "claude-desktop".into(),
            username: "testuser".into(),
            roles: vec!["admin".into()],
            subscriptions,
            teams,
        };
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("test key should load");
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KEY_KID.into());
        let token = encode(&header, &claims, &key).expect("token signing should succeed");

        let decoded = v.validate(&token).await.expect("token with plan data should decode");

        assert_eq!(decoded.roles, vec!["admin".to_string()]);
        assert_eq!(decoded.subscriptions["comad"].tier, "team");
        assert_eq!(decoded.subscriptions["comad"].status, "active");
        assert_eq!(decoded.teams["team-1"].role, "owner");
        assert_eq!(decoded.teams["team-1"].products, vec!["tack".to_string()]);
        assert_eq!(decoded.teams["team-1"].organization_id.as_deref(), Some("org-1"));
    }

    #[tokio::test]
    async fn validator_uses_jwks_cache_on_second_call() {
        let issuer = "http://localhost:8081";
        let audience = "http://localhost:8085/cunav/mcp";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .expect(1)  // JWKS must be fetched exactly once for two valid token validations
            .mount(&server)
            .await;

        let v = TokenValidator::new(
            format!("{}/oauth2/jwks", server.uri()),
            issuer,
            audience,
        );

        let token = mint_test_token(issuer, audience, "user-a", "read");
        v.validate(&token).await.expect("first validation should succeed");

        let token2 = mint_test_token(issuer, audience, "user-b", "write");
        v.validate(&token2).await.expect("second validation should succeed using cache");

        server.verify().await;
    }
}
