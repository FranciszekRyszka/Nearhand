//! The REST API, under `/api/v1`. The web console (`console`, served from
//! `/`) is built on it, so anything the console does, a script can.
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
//!
//! Every change goes in the audit log (`audit`), with who made it and from
//! where; so do sign-ins, failed ones included.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, FromRequestParts, Multipart, Path, Query, State,
};
use axum::http::header::{AUTHORIZATION, COOKIE, HOST, ORIGIN, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use nearhand_core::rendezvous::{FromServer, Refusal, ToServer};
use nearhand_core::wire;
use nearhand_transport::Fingerprint;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use tokio::sync::mpsc;

use crate::accounts::{Accounts, Refused, User};
use crate::audit::{Audit, Entry, Event};
use crate::devices::{Device, Devices, EnrollToken, Group};
use crate::grants::{GrantRule, Grants, UserGroup};
use crate::releases::{self, Listed, Releases};
use crate::rendezvous::Registry;
use crate::webtransport::Web;
use nearhand_core::grant::Role;
use nearhand_transport::Identity;

pub const SESSION_COOKIE: &str = "nearhand_session";

/// Where browsers without WebTransport, or on networks without UDP, carry
/// their session instead: the same relay, over this TCP connection.
pub const RELAY_PATH: &str = "/api/v1/relay";
/// The largest relayed packet taken from a browser. A QUIC packet in the
/// tunnel is about 1.2 kB; this leaves room and no more.
const MAX_RELAYED: usize = 16 * 1024;
/// How long a browser has to say which device it wants.
const RELAY_FIRST_MESSAGE: std::time::Duration = std::time::Duration::from_secs(10);
/// Packets waiting to go out to one browser. About a quarter of a megabyte
/// of video, after which the newest are dropped rather than queued.
const RELAY_QUEUE: usize = 200;

pub struct AppState {
    pub accounts: Arc<Accounts>,
    pub devices: Arc<Devices>,
    pub grants: Arc<Grants>,
    pub audit: Arc<Audit>,
    /// Agent releases, and which one agents are offered.
    pub releases: Arc<Releases>,
    /// The server's key, which signs grants.
    pub identity: Arc<Identity>,
    /// What browsers need to reach the QUIC side.
    pub web: Arc<Web>,
    /// Who is connected now.
    pub registry: Arc<Registry>,
    pub server: ServerInfo,
}

impl AppState {
    /// Put what `who` did in the audit log.
    async fn record(&self, who: &Caller, action: &str, target: &str, detail: Option<String>) {
        self.audit
            .record(Event {
                actor: Some(&who.user.name),
                address: who.from,
                action,
                target: Some(target),
                detail,
            })
            .await;
    }
}

/// What agents and viewers need to reach and pin this server.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerInfo {
    /// `host:port` of the QUIC side.
    pub address: String,
    pub fingerprint: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    let console = crate::console::router(&state.server.address);
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
        .route("/api/v1/server", get(server))
        .route("/api/v1/devices", get(list_devices))
        .route(
            "/api/v1/devices/{id}",
            get(get_device).patch(update_device).delete(delete_device),
        )
        .route("/api/v1/device-groups", get(list_groups).post(create_group))
        .route(
            "/api/v1/device-groups/{id}",
            patch(rename_group).delete(delete_group),
        )
        .route(
            "/api/v1/enroll-tokens",
            get(list_enroll_tokens).post(new_enroll_token),
        )
        .route("/api/v1/enroll-tokens/{id}", delete(delete_enroll_token))
        .route(
            "/api/v1/user-groups",
            get(list_user_groups).post(create_user_group),
        )
        .route(
            "/api/v1/user-groups/{id}",
            patch(rename_user_group).delete(delete_user_group),
        )
        .route(
            "/api/v1/user-groups/{id}/members/{user}",
            put(add_member).delete(remove_member),
        )
        .route("/api/v1/grants", get(list_grants).post(set_grant))
        .route("/api/v1/grants/{id}", delete(delete_grant))
        .route("/api/v1/audit", get(audit_log))
        .route(
            "/api/v1/releases",
            get(list_releases)
                .post(upload_release)
                // A package, and room for the form around it.
                .layer(DefaultBodyLimit::max(releases::MAX_PACKAGE + 64 * 1024)),
        )
        .route("/api/v1/releases/{id}", delete(delete_release))
        .route(
            "/api/v1/releases/{id}/offer",
            post(offer_release).delete(withdraw_release),
        )
        .route("/api/v1/devices/{id}/grant", post(device_grant))
        .route("/api/v1/webtransport", get(webtransport))
        .route(RELAY_PATH, get(relay))
        .merge(console)
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

/// The signed-in caller, by API token or session cookie, and where from.
pub struct Caller {
    pub user: User,
    pub from: Option<IpAddr>,
}

/// A caller who is an administrator.
pub struct Admin(pub Caller);

impl Deref for Admin {
    type Target = Caller;

    fn deref(&self) -> &Caller {
        &self.0
    }
}

fn address(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(from)| from.ip().to_canonical())
}

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let from = address(parts);
        if let Some(token) = bearer(&parts.headers) {
            let user = state.accounts.api_user(token).await?;
            return user
                .map(|user| Caller { user, from })
                .ok_or(ApiError::Unauthenticated);
        }
        let token = cookie(&parts.headers, SESSION_COOKIE).ok_or(ApiError::Unauthenticated)?;
        if !is_safe(&parts.method) && !same_origin(&parts.headers) {
            return Err(ApiError::CrossSite);
        }
        let user = state.accounts.session_user(&token).await?;
        user.map(|user| Caller { user, from })
            .ok_or(ApiError::Unauthenticated)
    }
}

impl FromRequestParts<Arc<AppState>> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let caller = Caller::from_request_parts(parts, state).await?;
        if !caller.user.admin {
            return Err(Refused::Forbidden.into());
        }
        Ok(Admin(caller))
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
    ConnectInfo(from): ConnectInfo<SocketAddr>,
    Json(request): Json<SetupRequest>,
) -> ApiResult<Json<User>> {
    let user = state
        .accounts
        .setup(&request.token, &request.name, &request.password)
        .await?;
    let who = Caller {
        user: user.clone(),
        from: Some(from.ip().to_canonical()),
    };
    state
        .record(
            &who,
            "setup",
            &user.name,
            Some("first administrator".into()),
        )
        .await;
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
    let from = from.ip().to_canonical();
    let signed_in = state
        .accounts
        .sign_in(
            &request.name,
            &request.password,
            request.totp.as_deref(),
            from,
        )
        .await;
    let (token, user) = match signed_in {
        Ok(signed_in) => signed_in,
        // Asked for the second factor: not a failure yet.
        Err(Refused::TotpNeeded) => return Err(Refused::TotpNeeded.into()),
        Err(refused) => {
            state
                .audit
                .record(Event {
                    actor: None,
                    address: Some(from),
                    action: "login.fail",
                    target: Some(&request.name),
                    detail: Some(refused.to_string()),
                })
                .await;
            return Err(refused.into());
        }
    };
    let who = Caller {
        user: user.clone(),
        from: Some(from),
    };
    state.record(&who, "login", &user.name, None).await;
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
    state
        .record(&caller, "password.change", &caller.user.name, None)
        .await;
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
    state
        .record(&caller, "totp.enable", &caller.user.name, None)
        .await;
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
    state
        .record(&caller, "totp.disable", &caller.user.name, None)
        .await;
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
    state
        .record(
            &caller,
            "token.create",
            &caller.user.name,
            Some(listed.name.clone()),
        )
        .await;
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
    state
        .record(
            &caller,
            "token.delete",
            &caller.user.name,
            Some(format!("#{id}")),
        )
        .await;
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
    admin: Admin,
    Json(request): Json<NewUserRequest>,
) -> ApiResult<(StatusCode, Json<User>)> {
    let user = state
        .accounts
        .create_user(&request.name, &request.password, request.admin)
        .await?;
    let detail = user.admin.then(|| "administrator".to_owned());
    state
        .record(&admin, "user.create", &user.name, detail)
        .await;
    Ok((StatusCode::CREATED, Json(user)))
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    admin: Option<bool>,
    disabled: Option<bool>,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
    Json(request): Json<UpdateUserRequest>,
) -> ApiResult<Json<User>> {
    let user = state
        .accounts
        .update_user(id, request.admin, request.disabled)
        .await?;
    state
        .record(
            &admin,
            "user.update",
            &user.name,
            Some(format!(
                "admin: {}, disabled: {}",
                user.admin, user.disabled
            )),
        )
        .await;
    Ok(Json(user))
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let name = state.accounts.user(id).await?.map(|u| u.name);
    state.accounts.delete_user(id).await?;
    state
        .record(
            &admin,
            "user.delete",
            &name.unwrap_or_else(|| format!("#{id}")),
            None,
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn server(State(state): State<Arc<AppState>>, _caller: Caller) -> Json<ServerInfo> {
    Json(state.server.clone())
}

// --- Devices ---------------------------------------------------------------------
//
// Administrators see every device and manage them; everyone sees the devices
// their grants let them at, with their role on each.

impl AppState {
    fn with_presence(&self, mut device: Device) -> Device {
        device.online = device
            .fingerprint
            .parse::<Fingerprint>()
            .ok()
            .and_then(|fingerprint| self.registry.online(&fingerprint))
            .is_some();
        device
    }
}

async fn list_devices(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> ApiResult<Json<Vec<Device>>> {
    let roles = state.roles(&caller.user).await?;
    let devices = state.devices.devices().await?;
    Ok(Json(
        devices
            .into_iter()
            .filter_map(|d| state.as_seen_by(&caller.user, &roles, d))
            .collect(),
    ))
}

async fn get_device(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<i64>,
) -> ApiResult<Json<Device>> {
    let roles = state.roles(&caller.user).await?;
    let device = state.devices.device(id).await?;
    // Not there, as far as someone without a grant can tell.
    state
        .as_seen_by(&caller.user, &roles, device)
        .map(Json)
        .ok_or(ApiError::Refused(Refused::NotFound))
}

impl AppState {
    /// `user`'s role on each device they may reach, by device row.
    async fn roles(&self, user: &User) -> ApiResult<HashMap<i64, Role>> {
        Ok(self
            .grants
            .reachable(user.id)
            .await?
            .into_iter()
            .map(|r| (r.id, r.role))
            .collect())
    }

    /// `device` as `user` sees it, if they may see it at all.
    fn as_seen_by(
        &self,
        user: &User,
        roles: &HashMap<i64, Role>,
        device: Device,
    ) -> Option<Device> {
        let role = roles.get(&device.id).copied();
        if role.is_none() && !user.admin {
            return None;
        }
        let mut device = self.with_presence(device);
        device.role = role.map(|r| r.as_str().to_owned());
        Some(device)
    }
}

/// A field that may be absent (leave it), null (clear it) or a value.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct UpdateDeviceRequest {
    name: Option<String>,
    /// A group's id, or null for none.
    #[serde(default, deserialize_with = "present")]
    group_id: Option<Option<i64>>,
}

async fn update_device(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
    Json(request): Json<UpdateDeviceRequest>,
) -> ApiResult<Json<Device>> {
    let device = state
        .devices
        .update_device(id, request.name.as_deref(), request.group_id)
        .await?;
    state
        .record(
            &admin,
            "device.update",
            &device.name,
            Some(format!(
                "group: {}",
                device.group.as_deref().unwrap_or("none")
            )),
        )
        .await;
    Ok(Json(state.with_presence(device)))
}

async fn delete_device(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let device = state.devices.device(id).await?;
    state.devices.delete_device(id).await?;
    state
        .record(
            &admin,
            "device.delete",
            &device.name,
            Some(device.device_id),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_groups(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> ApiResult<Json<Vec<Group>>> {
    Ok(Json(state.devices.groups().await?))
}

#[derive(Deserialize)]
struct GroupRequest {
    name: String,
}

async fn create_group(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Json(request): Json<GroupRequest>,
) -> ApiResult<(StatusCode, Json<Group>)> {
    let group = state.devices.create_group(&request.name).await?;
    state
        .record(&admin, "device_group.create", &group.name, None)
        .await;
    Ok((StatusCode::CREATED, Json(group)))
}

async fn rename_group(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
    Json(request): Json<GroupRequest>,
) -> ApiResult<Json<Group>> {
    let before = state.device_group_name(id).await?;
    let group = state.devices.rename_group(id, &request.name).await?;
    state
        .record(
            &admin,
            "device_group.rename",
            &before,
            Some(group.name.clone()),
        )
        .await;
    Ok(Json(group))
}

async fn delete_group(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let name = state.device_group_name(id).await?;
    state.devices.delete_group(id).await?;
    state
        .record(&admin, "device_group.delete", &name, None)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_enroll_tokens(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> ApiResult<Json<Vec<EnrollToken>>> {
    Ok(Json(state.devices.enroll_tokens().await?))
}

#[derive(Deserialize)]
struct NewEnrollTokenRequest {
    name: String,
    group_id: Option<i64>,
    /// How many devices it enrolls; none for any number.
    #[serde(default = "one")]
    uses: Option<u32>,
    #[serde(default = "one_day")]
    expires_in_days: u32,
}

fn one() -> Option<u32> {
    Some(1)
}

fn one_day() -> u32 {
    1
}

async fn new_enroll_token(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Json(request): Json<NewEnrollTokenRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let (listed, token) = state
        .devices
        .new_enroll_token(
            &admin.user,
            &request.name,
            request.group_id,
            request.uses,
            request.expires_in_days,
        )
        .await?;
    state
        .record(
            &admin,
            "enroll_token.create",
            &listed.name,
            Some(format!(
                "uses: {}, days: {}, group: {}",
                listed.uses_left.map_or("any".into(), |n| n.to_string()),
                request.expires_in_days,
                request.group_id.map_or("none".into(), |g| format!("#{g}"))
            )),
        )
        .await;
    let server = &state.server;
    // The token is in this answer and nowhere else, ever; so are the
    // commands that use it.
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "token": token,
            "details": listed,
            "install": format!(
                "nearhand-agent install --server {} --server-fingerprint {} --token {token}",
                server.address, server.fingerprint
            ),
            "msi": format!(
                "msiexec /i nearhand-agent.msi SERVER={} SERVER_FINGERPRINT={} ENROLL_TOKEN={token}",
                server.address, server.fingerprint
            ),
        })),
    ))
}

async fn delete_enroll_token(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let name = state
        .devices
        .enroll_tokens()
        .await?
        .into_iter()
        .find(|t| t.id == id)
        .map_or_else(|| format!("#{id}"), |t| t.name);
    state.devices.delete_enroll_token(id).await?;
    state
        .record(&admin, "enroll_token.delete", &name, None)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- User groups and grants ------------------------------------------------------------

async fn list_user_groups(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> ApiResult<Json<Vec<UserGroup>>> {
    Ok(Json(state.grants.user_groups().await?))
}

async fn create_user_group(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Json(request): Json<GroupRequest>,
) -> ApiResult<(StatusCode, Json<UserGroup>)> {
    let group = state.grants.create_user_group(&request.name).await?;
    state
        .record(&admin, "user_group.create", &group.name, None)
        .await;
    Ok((StatusCode::CREATED, Json(group)))
}

async fn rename_user_group(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
    Json(request): Json<GroupRequest>,
) -> ApiResult<Json<UserGroup>> {
    let before = state.grants.user_group(id).await?.name;
    let group = state.grants.rename_user_group(id, &request.name).await?;
    state
        .record(
            &admin,
            "user_group.rename",
            &before,
            Some(group.name.clone()),
        )
        .await;
    Ok(Json(group))
}

async fn delete_user_group(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let name = state.grants.user_group(id).await?.name;
    state.grants.delete_user_group(id).await?;
    state.record(&admin, "user_group.delete", &name, None).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path((id, user)): Path<(i64, i64)>,
) -> ApiResult<Json<UserGroup>> {
    let group = state.grants.add_member(id, user).await?;
    let name = state.user_name(user).await?;
    state
        .record(&admin, "user_group.add", &group.name, Some(name))
        .await;
    Ok(Json(group))
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path((id, user)): Path<(i64, i64)>,
) -> ApiResult<Json<UserGroup>> {
    let group = state.grants.remove_member(id, user).await?;
    let name = state.user_name(user).await?;
    state
        .record(&admin, "user_group.remove", &group.name, Some(name))
        .await;
    Ok(Json(group))
}

async fn list_grants(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> ApiResult<Json<Vec<GrantRule>>> {
    Ok(Json(state.grants.grants().await?))
}

#[derive(Deserialize)]
struct GrantRequest {
    user_group_id: i64,
    device_group_id: i64,
    role: String,
}

async fn set_grant(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Json(request): Json<GrantRequest>,
) -> ApiResult<(StatusCode, Json<GrantRule>)> {
    let role: Role = request
        .role
        .parse()
        .map_err(|e: String| ApiError::Refused(Refused::Invalid(e)))?;
    let rule = state
        .grants
        .set_grant(request.user_group_id, request.device_group_id, role)
        .await?;
    state
        .record(
            &admin,
            "grant.set",
            &format!("{} → {}", rule.user_group, rule.device_group),
            Some(rule.role.clone()),
        )
        .await;
    Ok((StatusCode::CREATED, Json(rule)))
}

async fn delete_grant(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let rule = state
        .grants
        .grants()
        .await?
        .into_iter()
        .find(|g| g.id == id)
        .ok_or(Refused::NotFound)?;
    state.grants.delete_grant(id).await?;
    state
        .record(
            &admin,
            "grant.delete",
            &format!("{} → {}", rule.user_group, rule.device_group),
            Some(rule.role),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

impl AppState {
    async fn device_group_name(&self, id: i64) -> ApiResult<String> {
        Ok(self
            .devices
            .groups()
            .await?
            .into_iter()
            .find(|g| g.id == id)
            .ok_or(Refused::NotFound)?
            .name)
    }

    async fn user_name(&self, id: i64) -> ApiResult<String> {
        Ok(self
            .accounts
            .user(id)
            .await?
            .map_or_else(|| format!("#{id}"), |u| u.name))
    }
}

// --- The web viewer -----------------------------------------------------------------

/// Where the web viewer connects, and the certificate hash its browser must
/// accept if the server's is self-signed.
async fn webtransport(
    State(state): State<Arc<AppState>>,
    _caller: Caller,
) -> Json<serde_json::Value> {
    let hashes: Vec<String> = state.web.hash().map(|h| hex(&h)).into_iter().collect();
    Json(json!({
        "url": format!("https://{}{}", state.server.address, crate::webtransport::PATH),
        "certificate_hashes": hashes,
    }))
}

/// A grant for the caller on device `id`, for the web viewer to present:
/// what a native viewer gets from the QUIC side with an API token.
async fn device_grant(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let reachable = state
        .grants
        .reachable(caller.user.id)
        .await?
        .into_iter()
        .find(|r| r.id == id);
    let Some(device) = reachable else {
        // As if it were not there: no grant says nothing about the device.
        state
            .record(
                &caller,
                "session.refuse",
                &format!("#{id}"),
                Some("no grant".into()),
            )
            .await;
        return Err(Refused::NotFound.into());
    };
    let signed = crate::grants::issue(&state.identity, &device, &caller.user.name)
        .map_err(|e| crate::accounts::internal(format!("{e:#}")))?;
    let bytes =
        postcard::to_stdvec(&signed).map_err(|e| crate::accounts::internal(e.to_string()))?;
    let device_id = device.fingerprint.device_id();
    state
        .record(
            &caller,
            "session.grant",
            &device_id.to_string(),
            Some(format!("{}, web", device.role)),
        )
        .await;
    Ok(Json(json!({
        "device_id": device_id.to_string(),
        "fingerprint": device.fingerprint.to_string(),
        "role": device.role.as_str(),
        "grant": hex(&bytes),
    })))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- The relay over TCP -----------------------------------------------------------

/// The web viewer's session, carried over this WebSocket instead of
/// WebTransport: for browsers without WebTransport, and networks that block
/// UDP. The first message asks to be introduced to a device, the answer
/// comes back as one message, and everything after that is the tunnel — the
/// same datagrams, which the server cannot read either way.
async fn relay(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    ConnectInfo(from): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    // A WebSocket carries the console's cookie, so it must come from the
    // console: another site must not tunnel through this server.
    if !same_origin(&headers) {
        return Err(ApiError::CrossSite);
    }
    tracing::debug!(user = %caller.user.name, %from, "a browser is relaying over TCP");
    Ok(upgrade
        .max_message_size(MAX_RELAYED)
        .on_upgrade(move |socket| async move {
            if let Err(e) = tunnel(socket, state, from).await {
                tracing::debug!(%from, error = %format!("{e:#}"), "the relay over TCP ended");
            }
        }))
}

async fn tunnel(socket: WebSocket, state: Arc<AppState>, from: SocketAddr) -> anyhow::Result<()> {
    use anyhow::{Context as _, bail};
    use futures_util::{SinkExt as _, StreamExt as _};

    let (mut writer, mut reader) = socket.split();
    let first = tokio::time::timeout(RELAY_FIRST_MESSAGE, reader.next())
        .await
        .context("no first message in time")?
        .context("the browser left")??;
    let Message::Binary(asked) = first else {
        bail!("the first message was not a request");
    };
    let asked: ToServer = framed(&asked)?;
    // A browser cannot be reached directly, so it gives no addresses.
    let arranged = match asked {
        ToServer::Connect { id, .. } => {
            crate::rendezvous::arrange(&state.registry, from, id, Vec::new(), None).await
        }
        _ => Err(Refusal::Protocol),
    };
    let introduction = match arranged {
        Ok(introduction) => introduction,
        Err(refusal) => {
            let answer = wire::encode(&FromServer::Refused(refusal))?;
            let _ = writer.send(Message::Binary(answer.into())).await;
            let _ = writer.close().await;
            return Ok(());
        }
    };
    // One message, so the page has the whole answer at once.
    let mut answer = Vec::new();
    for message in introduction.messages() {
        answer.extend_from_slice(&wire::encode(&message)?);
    }
    writer.send(Message::Binary(answer.into())).await?;

    // Bounded, and dropping what does not fit: a browser that reads slowly
    // must not pile the agent's video up in this server's memory. Datagrams
    // are droppable by definition — the viewer asks for the repair.
    let (out, sending) = mpsc::channel(RELAY_QUEUE);
    let writing = tokio::spawn(async move {
        let mut out: mpsc::Receiver<Bytes> = sending;
        while let Some(datagram) = out.recv().await {
            if writer.send(Message::Binary(datagram)).await.is_err() {
                break;
            }
        }
        let _ = writer.close().await;
    });
    introduction
        .relay(Arc::new(OverTcp {
            out,
            incoming: tokio::sync::Mutex::new(reader),
        }))
        .await;
    writing.abort();
    Ok(())
}

/// One length-prefixed message, as the wire carries them.
fn framed<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    use anyhow::Context as _;
    let header: [u8; wire::HEADER_LEN] = bytes
        .get(..wire::HEADER_LEN)
        .context("a message with no header")?
        .try_into()?;
    let body = bytes
        .get(wire::HEADER_LEN..wire::HEADER_LEN + wire::body_len(header)?)
        .context("a message cut short")?;
    Ok(wire::decode(body)?)
}

/// A browser's WebSocket, as the viewer's side of a tunnel.
struct OverTcp {
    out: mpsc::Sender<Bytes>,
    incoming: tokio::sync::Mutex<futures_util::stream::SplitStream<WebSocket>>,
}

impl nearhand_transport::relay::Carrier for OverTcp {
    fn send_datagram(&self, datagram: Bytes) -> bool {
        // Full means this browser is behind; the packet goes, not the
        // tunnel. Closed means it has left.
        !matches!(
            self.out.try_send(datagram),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    }

    fn read_datagram(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Bytes>> + Send + '_>> {
        use futures_util::StreamExt as _;
        Box::pin(async move {
            let mut incoming = self.incoming.lock().await;
            loop {
                match incoming.next().await {
                    Some(Ok(Message::Binary(packet))) => return Some(packet),
                    // Pings and the like are not the tunnel's.
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => return None,
                }
            }
        })
    }

    fn describe(&self) -> String {
        "a browser over TCP".to_owned()
    }
}

// --- Releases -------------------------------------------------------------------------

async fn list_releases(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> ApiResult<Json<Vec<Listed>>> {
    Ok(Json(state.releases.list().await?))
}

/// A package and its signature file, as `multipart/form-data` fields
/// `package` and `signature`: taken only if the release key signed it.
async fn upload_release(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    mut form: Multipart,
) -> ApiResult<(StatusCode, Json<Listed>)> {
    let unreadable = |e: axum::extract::multipart::MultipartError| {
        Refused::Invalid(format!("the upload could not be read: {}", e.body_text()))
    };
    let mut package = None;
    let mut signature = None;
    while let Some(field) = form.next_field().await.map_err(unreadable)? {
        match field.name() {
            Some("package") => package = Some(field.bytes().await.map_err(unreadable)?),
            Some("signature") => signature = Some(field.text().await.map_err(unreadable)?),
            _ => {}
        }
    }
    let (Some(package), Some(signature)) = (package, signature) else {
        return Err(Refused::Invalid(
            "send the package and its signature file, as the fields `package` and `signature`"
                .into(),
        )
        .into());
    };
    let release = state.releases.add(&package, &signature).await?;
    state
        .record(
            &admin,
            "release.upload",
            &release_name(&release),
            Some(release.sha256.clone()),
        )
        .await;
    Ok((StatusCode::CREATED, Json(release)))
}

async fn offer_release(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<Json<Listed>> {
    let release = state.releases.offer(id).await?;
    state
        .record(&admin, "release.offer", &release_name(&release), None)
        .await;
    Ok(Json(release))
}

async fn withdraw_release(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<Json<Listed>> {
    let release = state.releases.withdraw(id).await?;
    state
        .record(&admin, "release.withdraw", &release_name(&release), None)
        .await;
    Ok(Json(release))
}

async fn delete_release(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let release = state.releases.delete(id).await?;
    state
        .record(&admin, "release.delete", &release_name(&release), None)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `nearhand-agent 0.2.0 (windows-x86_64)`, for the audit log.
fn release_name(release: &Listed) -> String {
    format!(
        "{} {} ({})",
        release.product, release.version, release.platform
    )
}

// --- Audit log ----------------------------------------------------------------------

#[derive(Deserialize)]
struct AuditQuery {
    /// Entries older than this one: the last id of the page before.
    before: Option<i64>,
    #[serde(default = "page")]
    limit: u32,
}

fn page() -> u32 {
    100
}

async fn audit_log(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Vec<Entry>>> {
    Ok(Json(state.audit.entries(query.before, query.limit).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::testing;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    struct Api {
        app: Router,
        setup_token: String,
        devices: Arc<Devices>,
        accounts: Arc<Accounts>,
        /// The release key this server takes releases from.
        signer: crate::releases::tests::Signer,
        _releases: crate::releases::tests::tempdir::Dir,
    }

    async fn api() -> Api {
        let pool = crate::db::in_memory().await;
        let accounts = Arc::new(Accounts::new(pool.clone()));
        let setup_token = accounts.new_setup_token().await.expect("token");
        let devices = Arc::new(Devices::new(pool.clone()));
        let signer = crate::releases::tests::Signer::new();
        let releases_dir = crate::releases::tests::tempdir::Dir::new();
        let state = AppState {
            accounts: accounts.clone(),
            registry: Arc::new(Registry::new(devices.clone())),
            devices: devices.clone(),
            grants: Arc::new(Grants::new(pool.clone())),
            releases: Arc::new(Releases::new(
                pool.clone(),
                releases_dir.path().to_path_buf(),
                signer.public,
            )),
            audit: Arc::new(Audit::new(pool)),
            identity: Arc::new(Identity::generate().expect("server key")),
            web: Web::new(&crate::config::Config::default()).expect("web certificate"),
            server: ServerInfo {
                address: "desk.example.com:443".into(),
                fingerprint: "ab".repeat(32),
            },
        };
        let app = router(Arc::new(state))
            .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50000))));
        Api {
            app,
            setup_token,
            devices,
            accounts,
            signer,
            _releases: releases_dir,
        }
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

        /// Upload a package and its signature file, as the console's form
        /// does.
        async fn upload(&self, auth: &[(&str, &str)], package: &[u8], signature: &str) -> Answer {
            const BOUNDARY: &str = "nearhand-test-boundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\ncontent-disposition: form-data; name=\"package\"; \
                     filename=\"nearhand-agent.msi\"\r\ncontent-type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(package);
            body.extend_from_slice(
                format!(
                    "\r\n--{BOUNDARY}\r\ncontent-disposition: form-data; name=\"signature\"\r\n\r\n\
                     {signature}\r\n--{BOUNDARY}--\r\n"
                )
                .as_bytes(),
            );
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/releases")
                .header(HOST, "desk.example.com")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                );
            for (name, value) in auth {
                request = request.header(*name, *value);
            }
            let request = request.body(Body::from(body)).expect("request");
            let response = self.app.clone().oneshot(request).await.expect("response");
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            Answer {
                status,
                headers,
                body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
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

        async fn accounts_user(&self, name: &str) -> User {
            self.accounts
                .users()
                .await
                .expect("users")
                .into_iter()
                .find(|u| u.name == name)
                .expect("user")
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
    async fn enrolling_and_managing_devices() {
        let api = api().await;
        let admin = api.admin_cookie().await;
        let auth = [("cookie", admin.as_str())];
        let group = api
            .call(
                Method::POST,
                "/api/v1/device-groups",
                &auth,
                Some(json!({ "name": "Front office" })),
            )
            .await;
        assert_eq!(group.status, StatusCode::CREATED, "{}", group.body);
        let group_id = group.body["id"].as_i64().expect("id");

        let made = api
            .call(
                Method::POST,
                "/api/v1/enroll-tokens",
                &auth,
                Some(json!({ "name": "rollout", "group_id": group_id, "uses": null, "expires_in_days": 7 })),
            )
            .await;
        assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
        let token = made.body["token"].as_str().expect("token").to_owned();
        assert_eq!(made.body["details"]["uses_left"], serde_json::Value::Null);
        let install = made.body["install"].as_str().expect("command");
        assert!(
            install.contains("--server desk.example.com:443"),
            "{install}"
        );
        assert!(install.contains(&token));
        let listed = api
            .call(Method::GET, "/api/v1/enroll-tokens", &auth, None)
            .await;
        assert!(listed.body[0].get("token").is_none(), "never shown again");

        // An agent enrolls (on the QUIC side; here, straight in).
        let key = Fingerprint::from_bytes([7; 32]);
        api.devices
            .enroll(
                &key,
                &nearhand_core::rendezvous::Enrollment {
                    token,
                    name: "RECEPTION".into(),
                    os: "windows x86_64".into(),
                    version: "0.1.0".into(),
                },
                SocketAddr::from(([198, 51, 100, 7], 50000)),
            )
            .await
            .expect("enroll");

        let devices = api.call(Method::GET, "/api/v1/devices", &auth, None).await;
        assert_eq!(devices.status, StatusCode::OK);
        let device = &devices.body[0];
        assert_eq!(device["name"], "RECEPTION");
        assert_eq!(device["group"], "Front office");
        assert_eq!(device["online"], false, "enrolled, but not connected");
        assert_eq!(device["fingerprint"], key.to_string());
        let id = device["id"].as_i64().expect("id");

        let renamed = api
            .call(
                Method::PATCH,
                &format!("/api/v1/devices/{id}"),
                &auth,
                Some(json!({ "name": "Front desk" })),
            )
            .await;
        assert_eq!(renamed.body["name"], "Front desk");
        assert_eq!(renamed.body["group_id"], group_id, "absent: unchanged");
        let ungrouped = api
            .call(
                Method::PATCH,
                &format!("/api/v1/devices/{id}"),
                &auth,
                Some(json!({ "group_id": null })),
            )
            .await;
        assert_eq!(ungrouped.body["group_id"], serde_json::Value::Null);

        let removed = api
            .call(
                Method::DELETE,
                &format!("/api/v1/devices/{id}"),
                &auth,
                None,
            )
            .await;
        assert_eq!(removed.status, StatusCode::NO_CONTENT);
        let gone = api
            .call(Method::GET, &format!("/api/v1/devices/{id}"), &auth, None)
            .await;
        assert_eq!(gone.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn users_see_the_devices_their_grants_let_them_at() {
        let api = api().await;
        let admin = api.admin_cookie().await;
        let auth = [("cookie", admin.as_str())];
        let bob_id = api
            .call(
                Method::POST,
                "/api/v1/users",
                &auth,
                Some(json!({ "name": "bob", "password": "bobs long password" })),
            )
            .await
            .body["id"]
            .as_i64()
            .expect("bob");
        let bob = api.sign_in("bob", "bobs long password").await;
        for path in [
            "/api/v1/device-groups",
            "/api/v1/enroll-tokens",
            "/api/v1/user-groups",
            "/api/v1/grants",
        ] {
            let answer = api.call(Method::GET, path, &[("cookie", &bob)], None).await;
            assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}");
        }

        // Two devices, one in a group bob's group has a grant for.
        let office = api
            .call(
                Method::POST,
                "/api/v1/device-groups",
                &auth,
                Some(json!({ "name": "Office" })),
            )
            .await
            .body["id"]
            .as_i64()
            .expect("group");
        let mut ids = Vec::new();
        for (n, group) in [(1u8, Some(office)), (2, None)] {
            let (_, token) = api
                .devices
                .new_enroll_token(&api.accounts_user("ada").await, "t", group, Some(1), 1)
                .await
                .expect("token");
            let device = api
                .devices
                .enroll(
                    &Fingerprint::from_bytes([n; 32]),
                    &nearhand_core::rendezvous::Enrollment {
                        token,
                        name: format!("PC-{n}"),
                        os: "windows".into(),
                        version: "0.1.0".into(),
                    },
                    SocketAddr::from(([198, 51, 100, 7], 50000)),
                )
                .await
                .expect("enroll");
            ids.push(device.id);
        }
        let staff = api
            .call(
                Method::POST,
                "/api/v1/user-groups",
                &auth,
                Some(json!({ "name": "Staff" })),
            )
            .await;
        assert_eq!(staff.status, StatusCode::CREATED, "{}", staff.body);
        let staff = staff.body["id"].as_i64().expect("id");
        let joined = api
            .call(
                Method::PUT,
                &format!("/api/v1/user-groups/{staff}/members/{bob_id}"),
                &auth,
                None,
            )
            .await;
        assert_eq!(joined.body["members"][0]["name"], "bob");
        let bad = api
            .call(
                Method::POST,
                "/api/v1/grants",
                &auth,
                Some(json!({ "user_group_id": staff, "device_group_id": office, "role": "admin" })),
            )
            .await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST);
        let rule = api
            .call(
                Method::POST,
                "/api/v1/grants",
                &auth,
                Some(
                    json!({ "user_group_id": staff, "device_group_id": office, "role": "control" }),
                ),
            )
            .await;
        assert_eq!(rule.status, StatusCode::CREATED, "{}", rule.body);
        assert_eq!(rule.body["device_group"], "Office");

        let seen = api
            .call(Method::GET, "/api/v1/devices", &[("cookie", &bob)], None)
            .await;
        assert_eq!(seen.status, StatusCode::OK);
        let seen = seen.body.as_array().expect("list").clone();
        assert_eq!(seen.len(), 1, "only the granted one");
        assert_eq!(seen[0]["name"], "PC-1");
        assert_eq!(seen[0]["role"], "control");
        let hidden = api
            .call(
                Method::GET,
                &format!("/api/v1/devices/{}", ids[1]),
                &[("cookie", &bob)],
                None,
            )
            .await;
        assert_eq!(hidden.status, StatusCode::NOT_FOUND);
        let renamed = api
            .call(
                Method::PATCH,
                &format!("/api/v1/devices/{}", ids[0]),
                &[("cookie", &bob)],
                Some(json!({ "name": "mine" })),
            )
            .await;
        assert_eq!(
            renamed.status,
            StatusCode::FORBIDDEN,
            "seeing is not managing"
        );

        let all = api.call(Method::GET, "/api/v1/devices", &auth, None).await;
        assert_eq!(
            all.body.as_array().expect("list").len(),
            2,
            "admins see all"
        );
        assert_eq!(
            all.body[0]["role"],
            serde_json::Value::Null,
            "but reach none"
        );

        // The web viewer's grant: for bob on the device he may reach, not
        // on the other, nor for the administrator without a grant.
        let granted = api
            .call(
                Method::POST,
                &format!("/api/v1/devices/{}/grant", ids[0]),
                &[("cookie", &bob), ("origin", "https://desk.example.com")],
                None,
            )
            .await;
        assert_eq!(granted.status, StatusCode::OK, "{}", granted.body);
        assert_eq!(granted.body["role"], "control");
        let bytes: Vec<u8> = granted.body["grant"]
            .as_str()
            .expect("grant")
            .as_bytes()
            .chunks(2)
            .map(|h| u8::from_str_radix(std::str::from_utf8(h).expect("hex"), 16).expect("hex"))
            .collect();
        let signed: nearhand_core::grant::SignedGrant =
            postcard::from_bytes(&bytes).expect("a signed grant");
        let claims = signed.claims().expect("claims");
        assert_eq!(claims.user, "bob");
        assert_eq!(claims.device, [1u8; 32]);
        for (who, device) in [(&bob, ids[1]), (&admin, ids[0])] {
            let refused = api
                .call(
                    Method::POST,
                    &format!("/api/v1/devices/{device}/grant"),
                    &[("cookie", who)],
                    None,
                )
                .await;
            assert_eq!(refused.status, StatusCode::NOT_FOUND);
        }
        let from_elsewhere = api
            .call(
                Method::POST,
                &format!("/api/v1/devices/{}/grant", ids[0]),
                &[("cookie", &bob), ("origin", "https://evil.example")],
                None,
            )
            .await;
        assert_eq!(
            from_elsewhere.status,
            StatusCode::FORBIDDEN,
            "no grants for other sites"
        );
        let web = api
            .call(
                Method::GET,
                "/api/v1/webtransport",
                &[("cookie", &bob)],
                None,
            )
            .await;
        assert_eq!(web.body["url"], "https://desk.example.com:443/nearhand");
        assert_eq!(
            web.body["certificate_hashes"]
                .as_array()
                .expect("hashes")
                .len(),
            1
        );

        let server = api
            .call(Method::GET, "/api/v1/server", &[("cookie", &bob)], None)
            .await;
        assert_eq!(server.status, StatusCode::OK);
        assert_eq!(server.body["address"], "desk.example.com:443");
    }

    #[tokio::test]
    async fn the_console_is_served_locked_down() {
        let api = api().await;
        for (path, kind) in [
            ("/", "text/html"),
            ("/console.js", "text/javascript"),
            ("/console.css", "text/css"),
        ] {
            let request = Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = api.app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let headers = response.headers();
            assert!(
                headers[axum::http::header::CONTENT_TYPE]
                    .to_str()
                    .expect("type")
                    .starts_with(kind),
                "{path}"
            );
            let policy = headers[axum::http::header::CONTENT_SECURITY_POLICY]
                .to_str()
                .expect("policy");
            assert!(policy.contains("script-src 'self';") && !policy.contains("unsafe"));
            assert!(policy.contains("frame-ancestors 'none'"));
            assert!(
                policy.contains("connect-src 'self' https://desk.example.com:443;"),
                "the server's own WebTransport, and nothing else: {policy}"
            );
            assert_eq!(
                headers[axum::http::header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }

    #[tokio::test]
    async fn changes_and_sign_ins_go_in_the_audit_log() {
        let api = api().await;
        let admin = api.admin_cookie().await;
        let auth = [("cookie", admin.as_str())];
        api.call(
            Method::POST,
            "/api/v1/users",
            &auth,
            Some(json!({ "name": "bob", "password": "bobs long password" })),
        )
        .await;
        api.call(
            Method::POST,
            "/api/v1/login",
            &[],
            Some(json!({ "name": "bob", "password": "not bobs password" })),
        )
        .await;
        let bob = api.sign_in("bob", "bobs long password").await;
        let forbidden = api
            .call(Method::GET, "/api/v1/audit", &[("cookie", &bob)], None)
            .await;
        assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

        let log = api.call(Method::GET, "/api/v1/audit", &auth, None).await;
        assert_eq!(log.status, StatusCode::OK);
        let entries: Vec<(String, String, String)> = log
            .body
            .as_array()
            .expect("entries")
            .iter()
            .rev()
            .map(|e| {
                (
                    e["actor"].as_str().unwrap_or("-").to_owned(),
                    e["action"].as_str().expect("action").to_owned(),
                    e["target"].as_str().unwrap_or("-").to_owned(),
                )
            })
            .collect();
        let expected = [
            ("ada", "setup", "ada"),
            ("ada", "login", "ada"),
            ("ada", "user.create", "bob"),
            ("-", "login.fail", "bob"),
            ("bob", "login", "bob"),
        ];
        let expected: Vec<(String, String, String)> = expected
            .iter()
            .map(|(a, b, c)| ((*a).to_owned(), (*b).to_owned(), (*c).to_owned()))
            .collect();
        assert_eq!(entries, expected);
        assert_eq!(log.body[0]["address"], "192.0.2.1");

        let page = api
            .call(Method::GET, "/api/v1/audit?limit=2", &auth, None)
            .await;
        assert_eq!(page.body.as_array().expect("page").len(), 2);
        let last = page.body[1]["id"].as_i64().expect("id");
        let older = api
            .call(
                Method::GET,
                &format!("/api/v1/audit?before={last}"),
                &auth,
                None,
            )
            .await;
        assert_eq!(older.body.as_array().expect("older").len(), 3);
    }

    #[tokio::test]
    async fn administrators_upload_offer_and_withdraw_releases() {
        let api = api().await;
        let cookie = api.admin_cookie().await;
        let admin = [("cookie", cookie.as_str())];
        let (package, signature) = api.signer.package("0.2.0");

        // Signed by some other key: refused, whoever uploads it.
        let (other, other_signature) = crate::releases::tests::Signer::new().package("0.2.0");
        let refused = api.upload(&admin, &other, &other_signature).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
        let refused = api.upload(&admin, b"not it", &signature).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);

        let uploaded = api.upload(&admin, &package, &signature).await;
        assert_eq!(uploaded.status, StatusCode::CREATED, "{}", uploaded.body);
        assert_eq!(uploaded.body["version"], "0.2.0");
        assert_eq!(uploaded.body["offered"], false);
        let id = uploaded.body["id"].as_i64().expect("id");

        let offered = api
            .call(
                Method::POST,
                &format!("/api/v1/releases/{id}/offer"),
                &admin,
                None,
            )
            .await;
        assert_eq!(offered.status, StatusCode::OK, "{}", offered.body);
        assert_eq!(offered.body["offered"], true);
        let deleted = api
            .call(
                Method::DELETE,
                &format!("/api/v1/releases/{id}"),
                &admin,
                None,
            )
            .await;
        assert_eq!(deleted.status, StatusCode::BAD_REQUEST, "not while offered");
        let listed = api
            .call(Method::GET, "/api/v1/releases", &admin, None)
            .await;
        assert_eq!(listed.body.as_array().map(Vec::len), Some(1));
        assert_eq!(listed.body[0]["offered"], true);

        let withdrawn = api
            .call(
                Method::DELETE,
                &format!("/api/v1/releases/{id}/offer"),
                &admin,
                None,
            )
            .await;
        assert_eq!(withdrawn.body["offered"], false);
        let deleted = api
            .call(
                Method::DELETE,
                &format!("/api/v1/releases/{id}"),
                &admin,
                None,
            )
            .await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);

        // Administrators only.
        let made = api
            .call(
                Method::POST,
                "/api/v1/users",
                &admin,
                Some(json!({ "name": "bob", "password": "bobs long password" })),
            )
            .await;
        assert_eq!(made.status, StatusCode::CREATED);
        let bob = api.sign_in("bob", "bobs long password").await;
        let not_his = api.upload(&[("cookie", &bob)], &package, &signature).await;
        assert_eq!(not_his.status, StatusCode::FORBIDDEN);
        let not_his = api
            .call(Method::GET, "/api/v1/releases", &[("cookie", &bob)], None)
            .await;
        assert_eq!(not_his.status, StatusCode::FORBIDDEN);

        let log = api.call(Method::GET, "/api/v1/audit", &admin, None).await;
        let actions: Vec<&str> = log
            .body
            .as_array()
            .expect("entries")
            .iter()
            .filter_map(|e| e["action"].as_str())
            .filter(|a| a.starts_with("release."))
            .collect();
        assert_eq!(
            actions,
            [
                "release.delete",
                "release.withdraw",
                "release.offer",
                "release.upload"
            ]
        );
    }

    // --- The relay over TCP ----------------------------------------------

    /// The browser's side of the tunnel in the test: a WebSocket.
    struct OverWebSocket {
        out: mpsc::UnboundedSender<Bytes>,
        incoming: tokio::sync::Mutex<
            futures_util::stream::SplitStream<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
            >,
        >,
    }

    impl nearhand_transport::relay::Carrier for OverWebSocket {
        fn send_datagram(&self, datagram: Bytes) -> bool {
            self.out.send(datagram).is_ok()
        }

        fn read_datagram(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Bytes>> + Send + '_>>
        {
            use futures_util::StreamExt as _;
            Box::pin(async move {
                let mut incoming = self.incoming.lock().await;
                loop {
                    match incoming.next().await {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(packet))) => {
                            return Some(Bytes::from(packet.to_vec()));
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(_)) | None => return None,
                    }
                }
            })
        }

        fn describe(&self) -> String {
            "the test's browser".to_owned()
        }
    }

    /// Echo whatever a viewer sends on `endpoint`, so a tunnel can be
    /// shown to carry a session end to end.
    fn echo(endpoint: quinn::Endpoint) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(data) = recv.read_to_end(64 * 1024).await
                    {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                    conn.closed().await;
                });
            }
        });
    }

    /// A signed-in user's API token, an agent registered on the QUIC side
    /// and echoing whatever a viewer sends it, and the address of this
    /// server's HTTP side.
    async fn world_over_tcp() -> (
        String,
        SocketAddr,
        nearhand_core::rendezvous::DeviceId,
        Fingerprint,
    ) {
        use nearhand_transport::rendezvous::{Registration, stay_registered};
        use nearhand_transport::{rendezvous_endpoint, server_endpoint};

        let pool = crate::db::in_memory().await;
        let accounts = Arc::new(Accounts::new(pool.clone()));
        let setup = accounts.new_setup_token().await.expect("setup token");
        let user = accounts
            .setup(&setup, "ada", "correct horse battery")
            .await
            .expect("admin");
        let (_, token) = accounts
            .new_api_token(&user, "the browser", None)
            .await
            .expect("token");
        let devices = Arc::new(Devices::new(pool.clone()));
        let registry = Arc::new(Registry::new(devices.clone()));

        // The QUIC side, and an agent registered with it.
        let server_identity = Identity::generate().expect("server key");
        let quic = rendezvous_endpoint(([127, 0, 0, 1], 0).into(), &server_identity)
            .expect("rendezvous endpoint");
        let quic_addr = quic.local_addr().expect("addr");
        tokio::spawn(crate::rendezvous::serve(quic, registry.clone()));

        let agent = Arc::new(Identity::generate().expect("agent key"));
        let endpoint = server_endpoint(([127, 0, 0, 1], 0).into(), &agent).expect("agent endpoint");
        let (agent_id, agent_fp) = (agent.device_id(), agent.fingerprint());
        {
            // A relayed session arrives on the endpoint the agent is given
            // when it registers, not on its own socket.
            let agent = agent.clone();
            tokio::spawn(async move {
                let events = |event| {
                    if let Registration::Registered { relay } = event {
                        echo(relay);
                    }
                };
                stay_registered(
                    &endpoint,
                    quic_addr,
                    server_identity.fingerprint(),
                    &agent,
                    &testing(),
                    events,
                )
                .await;
            });
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while registry.online(&agent_fp).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the agent registers");

        // The HTTP side, on a port of its own.
        let releases_dir = crate::releases::tests::tempdir::Dir::new();
        let state = Arc::new(AppState {
            accounts,
            registry,
            devices,
            grants: Arc::new(Grants::new(pool.clone())),
            releases: Arc::new(Releases::new(
                pool.clone(),
                releases_dir.path().to_path_buf(),
                [0; 32],
            )),
            audit: Arc::new(Audit::new(pool)),
            identity: Arc::new(Identity::generate().expect("key")),
            web: Web::new(&crate::config::Config::default()).expect("web certificate"),
            server: ServerInfo {
                address: "localhost:443".into(),
                fingerprint: "ab".repeat(32),
            },
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("http listener");
        let http = listener.local_addr().expect("addr");
        let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        // The folder outlives the test through the state it was given to.
        std::mem::forget(releases_dir);
        (token, http, agent_id, agent_fp)
    }

    /// The whole fallback: a browser that cannot use UDP opens a WebSocket,
    /// is introduced, and runs its session with the agent inside it.
    #[tokio::test]
    async fn a_browser_reaches_an_agent_over_tcp() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use nearhand_core::rendezvous::{FromServer, ToServer};
        use nearhand_core::wire;
        use nearhand_transport::relay::{endpoint_over, relayed_address};
        use tokio_tungstenite::tungstenite::Message as Ws;

        let (token, http, agent_id, agent_fp) = world_over_tcp().await;
        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(format!("ws://{http}{RELAY_PATH}"))
            .header("host", http.to_string())
            .header("authorization", format!("Bearer {token}"))
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header(
                "sec-websocket-key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .expect("request");
        let (socket, _) = tokio_tungstenite::connect_async(request)
            .await
            .expect("the server takes the WebSocket");
        let (mut writer, mut reader) = socket.split();
        let asked = wire::encode(&ToServer::Connect {
            id: agent_id,
            addresses: Vec::new(),
        })
        .expect("encode");
        writer.send(Ws::Binary(asked.into())).await.expect("ask");
        let Some(Ok(Ws::Binary(answer))) = reader.next().await else {
            panic!("no answer");
        };
        let introduced: FromServer = framed(&answer).expect("answer");
        let FromServer::Peer { fingerprint, .. } = introduced else {
            panic!("not introduced: {introduced:?}");
        };
        assert_eq!(Fingerprint::from_bytes(fingerprint), agent_fp);

        // The session itself, inside the WebSocket: QUIC to the agent,
        // pinned to its key, which the server cannot read.
        let (out, mut sending) = mpsc::unbounded_channel::<Bytes>();
        tokio::spawn(async move {
            while let Some(packet) = sending.recv().await {
                if writer.send(Ws::Binary(packet)).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = endpoint_over(
            Arc::new(OverWebSocket {
                out,
                incoming: tokio::sync::Mutex::new(reader),
            }),
            false,
            None,
        )
        .expect("tunnel");
        let conn = tokio::time::timeout(
            Duration::from_secs(5),
            nearhand_transport::connect(&tunnel, relayed_address(0), agent_fp),
        )
        .await
        .expect("in time")
        .expect("end-to-end connection");
        let message: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let (mut send, mut recv) = conn.open_bi().await.expect("stream");
        send.write_all(&message).await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(64 * 1024).await.expect("echo");
        assert_eq!(echoed, message, "through the browser's TCP tunnel and back");
    }

    /// Without an account, no tunnel: the relay is not an open proxy.
    #[tokio::test]
    async fn the_relay_over_tcp_needs_an_account() {
        let (_, http, _, _) = world_over_tcp().await;
        let refused = tokio_tungstenite::connect_async(format!("ws://{http}{RELAY_PATH}")).await;
        assert!(refused.is_err(), "a stranger was let in");
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
