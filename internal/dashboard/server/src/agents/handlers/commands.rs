use crate::{
    agents::ws_hub, auth::middleware::AuthUser, crypto::cmd::sign_command, error::AppError,
    state::AppState,
};
use axum::{
    extract::{Extension, Path, State},
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct SendCommandRequest {
    /// Command forwarded to the agent, e.g. {"type":"container.start", ...}.
    #[serde(rename = "type")]
    pub cmd_type: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

pub async fn relay_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let agent = sqlx::query!(
        "SELECT wg_ip::text AS wg_ip, api_port FROM agents WHERE id = $1",
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let url = format!("https://{}:{}/heartbeat", agent.wg_ip, agent.api_port);

    let token = &*state.config.internal_token;
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            sqlx::query!(
                "UPDATE agents SET status='online', last_heartbeat=NOW() WHERE id=$1",
                id
            )
            .execute(&state.db)
            .await?;
            Ok(axum::http::StatusCode::NO_CONTENT)
        }
        Ok(r) => {
            let status_code = r.status().as_u16();
            let is_lockdown = status_code == 423;
            let new_status = if is_lockdown { "lockdown" } else { "offline" };
            sqlx::query!(
                "UPDATE agents SET status=$1, last_heartbeat=NOW() WHERE id=$2",
                new_status,
                id
            )
            .execute(&state.db)
            .await?;
            Err(AppError::BadGateway)
        }
        Err(_) => {
            sqlx::query!("UPDATE agents SET status='offline' WHERE id=$1", id)
                .execute(&state.db)
                .await?;
            Err(AppError::BadGateway)
        }
    }
}

pub async fn send_command(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<SendCommandRequest>,
) -> Result<impl IntoResponse, AppError> {
    let agent = sqlx::query!(
        "SELECT wg_ip, api_port, status FROM agents WHERE id = $1",
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    if agent.status == "lockdown" || agent.status == "offline" {
        return Err(AppError::AgentUnavailable);
    }

    let level = crate::auth::perms::user_vps_level(&state.db, user.user_id)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or(AppError::Forbidden)?;
    let command = serde_json::json!({ "type": req.cmd_type, "payload": req.payload });
    let signed = sign_command(&state.config, id, user.user_id, level.as_str(), &command)?;

    // Try WS first if agent has active connection.
    let signed_val = serde_json::to_value(&signed).unwrap_or(serde_json::json!({}));
    if let Some(body) = ws_hub::push_command(&state, id, signed_val).await {
        let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let code = if ok {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::BAD_GATEWAY
        };
        return Ok((code, Json(body)));
    }

    // Fallback: HTTP POST to agent's /cmd endpoint.
    let url = format!("https://{}:{}/cmd", agent.wg_ip, agent.api_port);

    let token = &*state.config.internal_token;
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&signed)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|_| AppError::BadGateway)?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({}));

    Ok((
        axum::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        Json(body),
    ))
}

pub async fn reboot_agent(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let agent = sqlx::query!(
        "SELECT wg_ip, api_port, status FROM agents WHERE id = $1",
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    if agent.status == "lockdown" || agent.status == "offline" {
        return Err(AppError::AgentUnavailable);
    }

    let level = crate::auth::perms::user_vps_level(&state.db, user.user_id)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or(AppError::Forbidden)?;
    if level < crate::auth::perms::CmdLevel::Write {
        return Err(AppError::Forbidden);
    }

    let command = json!({ "type": "vps.reboot" });
    let signed = sign_command(&state.config, id, user.user_id, "destructive", &command)?;

    sqlx::query!(
        "INSERT INTO agent_events (id, agent_id, event, detail) VALUES ($1, $2, $3, $4)",
        Uuid::now_v7(),
        id,
        "rebooting",
        format!("requested_by={}", user.user_id),
    )
    .execute(&state.db)
    .await?;

    // Try WS first.
    let signed_val = serde_json::to_value(&signed).unwrap_or_default();
    if let Some(body) = ws_hub::push_command(&state, id, signed_val).await {
        let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let code = if ok {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::BAD_GATEWAY
        };
        return Ok((code, Json(body)));
    }

    // Fallback HTTP.
    let url = format!("https://{}:{}/cmd", agent.wg_ip, agent.api_port);
    let tok = &*state.config.internal_token;
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {tok}"))
        .json(&signed)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| AppError::BadGateway)?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({ "ok": true }));
    Ok((
        axum::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        Json(body),
    ))
}
