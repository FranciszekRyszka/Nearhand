//! The REST API, under `/api/v1`. The console (M5, later) is built on it,
//! so anything the console does, a script can.
//!
//! Two ways to be someone:
//!
//! * `Authorization: Bearer nht_…` — an API token, for scripts.
//! * The `nearhand_session` cookie that `POST /login` sets — for the
//!   console. `HttpOnly`, `Secure`, `SameSite=Strict`; requests that change
//!   anything with it must also come from this server's own origin, if the
//!   browser says where they come from.
//!
//! Errors are `{"error": "…"}` with a fitting status; signing in without a
//! needed TOTP code also says `"totp_needed": true`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::header::{AUTHORIZATION, COOKIE, HOST, ORIGIN, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::accounts::{Accounts, Refused, User};

pub const SESSION_COOKIE: &str = "nearhand_session";

pub struct AppState {
    pub accounts: Accounts,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/setup", post(setup))
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", post(change_password))
        .route("/api/v1/me/totp", post(totp_begin))
        .route("/api/v1/me/totp/confirm", post(totp_confirm))
        .route("/api/v1/me/totp/disable", post(totp_disable))
        .route("/api/v1/me/tokens", get(list_tokens).post(new_token))
        .route("/api/v1/me/tokens/{id}", delete(delete_token))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", patch(update_user).delete(delete_user))
        .with_state(state)
}

// --- Errors -------------------------------------------------------------------

pub enum ApiError {
    Refused(Refused),
    Unauthenticated,
    CrossSite,
}

impl From<Refused> for ApiError {
    fn from(refused: Refused) -> Self {
        Self::Refused(refused)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::Unauthenticated => (StatusCode::UNAUTHORIZED, "sign in first".to_owned()),
            ApiError::CrossSite => (
                StatusCode::FORBIDDEN,
                "request from another site refused".to_owned(),
            ),
            ApiError::Refused(refused) => {
                let status = match refused {
                    Refused::WrongCredentials | Refused::TotpNeeded | Refused::WrongCode => {
                        StatusCode::UNAUTHORIZED
                    }
                    Refused::TooManyAttempts => StatusCode::TOO_MANY_REQUESTS,
                    Refused::Invalid(_) => StatusCode::BAD_REQUEST,
                    Refused::Forbidden => StatusCode::FORBIDDEN,
                    Refused::NotFound => StatusCode::NOT_FOUND,
                };
                (status, refused.to_string())
            }
        };
        let totp_needed = matches!(self, ApiError::Refused(Refused::TotpNeeded));
        let body = if totp_needed {
            json!({ "error": message, "totp_needed": true })
        } else {
            json!({ "error": message })
        };
        (status, Json(body)).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// --- Who is asking --------------------------------------------------------------

/// The signed-in caller, by API token or session cookie.
pub struct Caller {
    pub user: User,
}

/// A caller who is an administrator.
pub struct Admin(pub User);

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(token) = bearer(&parts.headers) {
            let user = state.accounts.api_user(token).await?;
            return user
                .map(|user| Caller { user })
                .ok_or(ApiError::Unauthenticated);
        }
        let token = cookie(&parts.headers, SESSION_COOKIE).ok_or(ApiError::Unauthenticated)?;
        if !is_safe(&parts.method) && !same_origin(&parts.headers) {
            return Err(ApiError::CrossSite);
        }
        let user = state.accounts.session_user(&token).await?;
        user.map(|user| Caller { user })
            .ok_or(ApiError::Unauthenticated)
    }
}

impl FromRequestParts<Arc<AppState>> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let Caller { user } = Caller::from_request_parts(parts, state).await?;
        if !user.admin {
            return Err(Refused::Forbidden.into());
        }
        Ok(Admin(user))
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Whether a request with the session cookie came from this server's own
/// pages. Browsers send `Origin` on such requests; one that names another
/// host is refused. (With `SameSite=Strict` the cookie should not even
/// arrive from elsewhere — this is the second lock.)
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let host = headers.get(HOST).and_then(|v| v.to_str().ok());
    let origin_host = origin
        .split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/'));
    matches!((origin_host, host), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
}

fn session_cookie(token: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

// --- Handlers -------------------------------------------------------------------

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Deserialize)]
struct SetupRequest {
    token: String,
    name: String,
    password: String,
}

async fn setup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SetupRequest>,
) -> ApiResult<Json<User>> {
    let user = state
        .accounts
        .setup(&request.token, &request.name, &request.password)
        .await?;
    tracing::info!(name = %user.name, "first administrator created");
    Ok(Json(user))
}

#[derive(Deserialize)]
struct LoginRequest {
    name: String,
    password: String,
    totp: Option<String>,
}

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(from): ConnectInfo<SocketAddr>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    let (token, user) = state
        .accounts
        .sign_in(
            &request.name,
            &request.password,
            request.totp.as_deref(),
            from.ip(),
        )
        .await?;
    let mut response = Json(user).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, session_cookie(&token, 12 * 3600));
    Ok(response)
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = cookie(&headers, SESSION_COOKIE) {
        state.accounts.sign_out(&token).await?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, session_cookie("", 0));
    Ok(response)
}

async fn me(caller: Caller) -> Json<User> {
    Json(caller.user)
}

#[derive(Deserialize)]
struct PasswordRequest {
    current: String,
    new: String,
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<StatusCode> {
    state
        .accounts
        .change_password(&caller.user, &request.current, &request.new)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn totp_begin(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> ApiResult<Json<serde_json::Value>> {
    let (secret, uri) = state.accounts.totp_begin(&caller.user).await?;
    Ok(Json(json!({ "secret": secret, "uri": uri })))
}

#[derive(Deserialize)]
struct CodeRequest {
    code: String,
}

async fn totp_confirm(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Json(request): Json<CodeRequest>,
) -> ApiResult<StatusCode> {
    state
        .accounts
        .totp_confirm(&caller.user, &request.code)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn totp_disable(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Json(request): Json<CodeRequest>,
) -> ApiResult<StatusCode> {
    state
        .accounts
        .totp_disable(&caller.user, &request.code)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_tokens(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> ApiResult<Json<serde_json::Value>> {
    let tokens = state.accounts.api_tokens(&caller.user).await?;
    Ok(Json(json!(tokens)))
}

#[derive(Deserialize)]
struct NewTokenRequest {
    name: String,
    /// Days until it stops working; none for never.
    expires_in_days: Option<u32>,
}

async fn new_token(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Json(request): Json<NewTokenRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let (listed, token) = state
        .accounts
        .new_api_token(&caller.user, &request.name, request.expires_in_days)
        .await?;
    // The token itself is in this answer and nowhere else, ever.
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": token, "details": listed })),
    ))
}

async fn delete_token(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    state.accounts.delete_api_token(&caller.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> ApiResult<Json<Vec<User>>> {
    Ok(Json(state.accounts.users().await?))
}

#[derive(Deserialize)]
struct NewUserRequest {
    name: String,
    password: String,
    #[serde(default)]
    admin: bool,
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    Admin(admin): Admin,
    Json(request): Json<NewUserRequest>,
) -> ApiResult<(StatusCode, Json<User>)> {
    let user = state
        .accounts
        .create_user(&request.name, &request.password, request.admin)
        .await?;
    tracing::info!(by = %admin.name, name = %user.name, admin = user.admin, "user created");
    Ok((StatusCode::CREATED, Json(user)))
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    admin: Option<bool>,
    disabled: Option<bool>,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Admin(admin): Admin,
    Path(id): Path<i64>,
    Json(request): Json<UpdateUserRequest>,
) -> ApiResult<Json<User>> {
    let user = state
        .accounts
        .update_user(id, request.admin, request.disabled)
        .await?;
    tracing::info!(by = %admin.name, name = %user.name, admin = user.admin, disabled = user.disabled, "user changed");
    Ok(Json(user))
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Admin(admin): Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    state.accounts.delete_user(id).await?;
    tracing::info!(by = %admin.name, id, "user deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct Api {
        app: Router,
        setup_token: String,
    }

    async fn api() -> Api {
        let accounts = Accounts::new(crate::db::in_memory().await);
        let setup_token = accounts.new_setup_token().await.expect("token");
        let app = router(Arc::new(AppState { accounts }))
            .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50000))));
        Api { app, setup_token }
    }

    struct Answer {
        status: StatusCode,
        headers: HeaderMap,
        body: serde_json::Value,
    }

    impl Api {
        async fn call(
            &self,
            method: Method,
            path: &str,
            auth: &[(&str, &str)],
            body: Option<serde_json::Value>,
        ) -> Answer {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(HOST, "desk.example.com");
            for (name, value) in auth {
                request = request.header(*name, *value);
            }
            let request = match body {
                Some(body) => request
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string())),
                None => request.body(Body::empty()),
            }
            .expect("request");
            let response = self.app.clone().oneshot(request).await.expect("response");
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            Answer {
                status,
                headers,
                body,
            }
        }

        /// Set up the first administrator and sign in: the session cookie.
        async fn admin_cookie(&self) -> String {
            let answer = self
                .call(
                    Method::POST,
                    "/api/v1/setup",
                    &[],
                    Some(json!({
                        "token": self.setup_token,
                        "name": "ada",
                        "password": "correct horse battery"
                    })),
                )
                .await;
            assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
            self.sign_in("ada", "correct horse battery").await
        }

        async fn sign_in(&self, name: &str, password: &str) -> String {
            let answer = self
                .call(
                    Method::POST,
                    "/api/v1/login",
                    &[],
                    Some(json!({ "name": name, "password": password })),
                )
                .await;
            assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
            let set_cookie = answer.headers[SET_COOKIE].to_str().expect("cookie");
            assert!(set_cookie.contains("HttpOnly"));
            assert!(set_cookie.contains("SameSite=Strict"));
            assert!(set_cookie.contains("Secure"));
            set_cookie.split(';').next().expect("pair").to_owned()
        }
    }

    #[tokio::test]
    async fn health_needs_no_one() {
        let api = api().await;
        let answer = api.call(Method::GET, "/api/v1/health", &[], None).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body["ok"], true);
    }

    #[tokio::test]
    async fn signing_in_and_out_with_the_cookie() {
        let api = api().await;
        let cookie = api.admin_cookie().await;
        let me = api
            .call(Method::GET, "/api/v1/me", &[("cookie", &cookie)], None)
            .await;
        assert_eq!(me.status, StatusCode::OK);
        assert_eq!(me.body["name"], "ada");
        assert_eq!(me.body["admin"], true);

        let out = api
            .call(Method::POST, "/api/v1/logout", &[("cookie", &cookie)], None)
            .await;
        assert_eq!(out.status, StatusCode::NO_CONTENT);
        let me = api
            .call(Method::GET, "/api/v1/me", &[("cookie", &cookie)], None)
            .await;
        assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nobody_is_anybody_without_credentials() {
        let api = api().await;
        for path in ["/api/v1/me", "/api/v1/users", "/api/v1/me/tokens"] {
            let answer = api.call(Method::GET, path, &[], None).await;
            assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{path}");
            assert!(answer.body["error"].is_string());
        }
        let wrong = api
            .call(
                Method::POST,
                "/api/v1/login",
                &[],
                Some(json!({ "name": "ada", "password": "nope nope nope" })),
            )
            .await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_tokens_work_as_bearer_tokens() {
        let api = api().await;
        let cookie = api.admin_cookie().await;
        let made = api
            .call(
                Method::POST,
                "/api/v1/me/tokens",
                &[("cookie", &cookie)],
                Some(json!({ "name": "script" })),
            )
            .await;
        assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
        let token = made.body["token"].as_str().expect("token").to_owned();
        let bearer = format!("Bearer {token}");
        let users = api
            .call(
                Method::GET,
                "/api/v1/users",
                &[("authorization", &bearer)],
                None,
            )
            .await;
        assert_eq!(users.status, StatusCode::OK);
        assert_eq!(users.body[0]["name"], "ada");

        let listed = api
            .call(
                Method::GET,
                "/api/v1/me/tokens",
                &[("cookie", &cookie)],
                None,
            )
            .await;
        assert!(listed.body[0].get("token").is_none(), "never shown again");
        let id = listed.body[0]["id"].as_i64().expect("id");
        let deleted = api
            .call(
                Method::DELETE,
                &format!("/api/v1/me/tokens/{id}"),
                &[("cookie", &cookie)],
                None,
            )
            .await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        let after = api
            .call(
                Method::GET,
                "/api/v1/me",
                &[("authorization", &bearer)],
                None,
            )
            .await;
        assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn only_administrators_manage_users() {
        let api = api().await;
        let cookie = api.admin_cookie().await;
        let made = api
            .call(
                Method::POST,
                "/api/v1/users",
                &[("cookie", &cookie)],
                Some(json!({ "name": "bob", "password": "bobs long password" })),
            )
            .await;
        assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
        assert_eq!(made.body["admin"], false);

        let bob = api.sign_in("bob", "bobs long password").await;
        let listed = api
            .call(Method::GET, "/api/v1/users", &[("cookie", &bob)], None)
            .await;
        assert_eq!(listed.status, StatusCode::FORBIDDEN);
        let promoted = api
            .call(
                Method::PATCH,
                &format!("/api/v1/users/{}", made.body["id"]),
                &[("cookie", &bob)],
                Some(json!({ "admin": true })),
            )
            .await;
        assert_eq!(promoted.status, StatusCode::FORBIDDEN, "not by himself");
    }

    #[tokio::test]
    async fn cookie_requests_from_another_site_are_refused() {
        let api = api().await;
        let cookie = api.admin_cookie().await;
        let from_elsewhere = api
            .call(
                Method::POST,
                "/api/v1/me/tokens",
                &[("cookie", &cookie), ("origin", "https://evil.example")],
                Some(json!({ "name": "stolen" })),
            )
            .await;
        assert_eq!(from_elsewhere.status, StatusCode::FORBIDDEN);
        let from_here = api
            .call(
                Method::POST,
                "/api/v1/me/tokens",
                &[("cookie", &cookie), ("origin", "https://desk.example.com")],
                Some(json!({ "name": "mine" })),
            )
            .await;
        assert_eq!(from_here.status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn setup_cannot_be_repeated() {
        let api = api().await;
        let _ = api.admin_cookie().await;
        let again = api
            .call(
                Method::POST,
                "/api/v1/setup",
                &[],
                Some(json!({
                    "token": api.setup_token,
                    "name": "mallory",
                    "password": "mallorys password"
                })),
            )
            .await;
        assert_eq!(again.status, StatusCode::FORBIDDEN);
    }
}
