use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{upstream_uri, AppState, GatewayError};

pub async fn get_json<T: DeserializeOwned>(
    state: &AppState,
    path: &str,
) -> Result<T, GatewayError> {
    let (status, _, body) =
        send_raw(state, Method::GET, path, HeaderMap::new(), Bytes::new()).await?;
    decode_json(status, body)
}

pub async fn post_json<T, B>(state: &AppState, path: &str, body: &B) -> Result<T, GatewayError>
where
    T: DeserializeOwned,
    B: Serialize,
{
    let bytes = serde_json::to_vec(body).map_err(GatewayError::internal)?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let (status, _, body) =
        send_raw(state, Method::POST, path, headers, Bytes::from(bytes)).await?;
    decode_json(status, body)
}

pub async fn post_empty_json<T: DeserializeOwned>(
    state: &AppState,
    path: &str,
) -> Result<T, GatewayError> {
    let (status, _, body) =
        send_raw(state, Method::POST, path, HeaderMap::new(), Bytes::new()).await?;
    decode_json(status, body)
}

pub async fn delete_json<T: DeserializeOwned>(
    state: &AppState,
    path: &str,
) -> Result<T, GatewayError> {
    let (status, _, body) =
        send_raw(state, Method::DELETE, path, HeaderMap::new(), Bytes::new()).await?;
    decode_json(status, body)
}

pub async fn post_text(state: &AppState, path: &str) -> Result<String, GatewayError> {
    let (status, _, body) =
        send_raw(state, Method::POST, path, HeaderMap::new(), Bytes::new()).await?;
    decode_text(status, body)
}

pub async fn send_raw(
    state: &AppState,
    method: Method,
    path: &str,
    mut headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), GatewayError> {
    #[cfg(feature = "mock")]
    if state.api_token.is_none() {
        return crate::mock::handle(method, path, body).await;
    }

    let token = state
        .api_token
        .as_deref()
        .ok_or_else(|| GatewayError::bad_gateway("missing upstream API token"))?;
    crate::rewrite_headers(&mut headers, token)?;
    let request = axum::http::Request::builder()
        .method(method)
        .uri(upstream_uri(path)?)
        .body(Full::new(body))
        .map_err(GatewayError::internal)?;
    let (mut parts, body) = request.into_parts();
    parts.headers = headers;
    let response = state
        .client
        .request(axum::http::Request::from_parts(parts, body))
        .await
        .map_err(GatewayError::bad_gateway)?;
    let (parts, body) = response.into_parts();
    let body = body.collect().await.map_err(GatewayError::bad_gateway)?;
    Ok((parts.status, parts.headers, body.to_bytes()))
}

fn decode_json<T: DeserializeOwned>(status: StatusCode, body: Bytes) -> Result<T, GatewayError> {
    if !status.is_success() {
        return Err(GatewayError::bad_gateway(decode_lossy(body)));
    }
    serde_json::from_slice(&body).map_err(GatewayError::bad_gateway)
}

fn decode_text(status: StatusCode, body: Bytes) -> Result<String, GatewayError> {
    let text = decode_lossy(body);
    if !status.is_success() {
        return Err(GatewayError::bad_gateway(text));
    }
    Ok(text)
}

fn decode_lossy(body: Bytes) -> String {
    String::from_utf8_lossy(&body).into_owned()
}
