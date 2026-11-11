use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use netcontrol_core::models::{AuthSession, Role, User};
use netcontrol_core::security::{self, verify_password};
use std::net::IpAddr;
use std::sync::Arc;

pub struct AuthUser {
    pub user: User,
    pub token_hash: String,
}

impl AuthUser {
    pub fn admin(&self) -> Result<(), ApiError> {
        if self.user.role == Role::Admin {
            Ok(())
        } else {
            Err(ApiError::forbidden(
                "administrator role required for this operation",
            ))
        }
    }
}

fn token_from_headers(parts: &Parts) -> Option<String> {
    if let Some(value) = parts.headers.get(AUTHORIZATION) {
        if let Ok(text) = value.to_str() {
            if let Some(token) = text.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }
    parts
        .headers
        .get("x-api-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = token_from_headers(parts).ok_or_else(ApiError::unauthorized)?;
        let digest = security::token_digest(&token);
        let user = state
            .db
            .validate_session(&digest)
            .map_err(ApiError::from)?
            .ok_or_else(ApiError::unauthorized)?;
        Ok(Self {
            user,
            token_hash: digest,
        })
    }
}

pub fn token_from_query(query: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key == "token" || key == "access_token" {
            let value = value.replace("%2B", "+").replace("%2F", "/");
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Authenticate a username/password pair, enforce the per-IP limit and issue
/// an opaque session token. Passwords are verified off the async runtime.
pub async fn login(
    state: &Arc<AppState>,
    username: &str,
    password: &str,
    remote_ip: Option<IpAddr>,
    user_agent: Option<&str>,
) -> Result<AuthSession, ApiError> {
    let ip = remote_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    {
        let mut limiter = state
            .login_limiter
            .lock()
            .map_err(|_| ApiError::internal("login limiter unavailable"))?;
        if !limiter.allowed(ip) {
            state
                .db
                .audit(
                    username,
                    "login",
                    None,
                    "throttled",
                    Some("too many failed login attempts"),
                    Some(&ip.to_string()),
                )
                .ok();
            return Err(ApiError::new(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many login attempts; try again in a few minutes",
            ));
        }
    }

    let user = state.db.find_user(username).map_err(ApiError::from)?;
    let verified = match &user {
        Some(user) if !user.disabled => {
            let password = password.to_string();
            let hash = user.password_hash.clone();
            tokio::task::spawn_blocking(move || verify_password(&password, &hash))
                .await
                .unwrap_or(false)
        }
        Some(_) => false,
        None => {
            // Keep unknown-user timing close to a failed Argon2 verification.
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            false
        }
    };
    if !verified {
        if let Ok(mut limiter) = state.login_limiter.lock() {
            limiter.record_failure(ip);
        }
        state
            .db
            .audit(
                username,
                "login",
                None,
                "failed",
                Some("invalid credentials"),
                Some(&ip.to_string()),
            )
            .ok();
        return Err(ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        ));
    }
    let mut user = user.expect("verified user exists");
    if user.disabled {
        return Err(ApiError::forbidden("this account is disabled"));
    }
    if let Ok(mut limiter) = state.login_limiter.lock() {
        limiter.clear(ip);
    }
    let (token, digest) = security::generate_token();
    let hours = state.config.server.session_hours.clamp(1, 720);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(hours))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    state
        .db
        .create_session(&digest, &user.id, &expires_at, user_agent)
        .map_err(ApiError::from)?;
    state.db.prune_expired_sessions().ok();
    state
        .db
        .audit(
            &user.username,
            "login",
            Some(&user.id),
            "success",
            Some("session issued"),
            Some(&ip.to_string()),
        )
        .ok();
    if user.role == Role::Admin {
        state.remove_password_file();
    }
    // Never return the password hash to a client.
    user.password_hash.clear();
    Ok(AuthSession {
        token,
        expires_at,
        user: user.into(),
    })
}

pub fn logout(state: &Arc<AppState>, auth: &AuthUser) -> Result<(), ApiError> {
    state
        .db
        .revoke_session(&auth.token_hash)
        .map_err(ApiError::from)?;
    state
        .db
        .audit(
            &auth.user.username,
            "logout",
            Some(&auth.user.id),
            "success",
            None,
            None,
        )
        .ok();
    Ok(())
}
