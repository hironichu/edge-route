mod agent;
#[cfg(feature = "mock")]
mod mock;
mod ui;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, CONNECTION, HOST, TRANSFER_ENCODING};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use axum::response::{Html, IntoResponse};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UnixStream};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tower_service::Service;
use tracing_subscriber::EnvFilter;

type ClientBody = Full<Bytes>;
type UnixClient = Client<UnixConnector, ClientBody>;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_AGENT_SOCKET: &str = "/run/edge-router/edge-agent.sock";
const DEFAULT_STATIC_DIR: &str = "web/edgeroute-ui";
const MAX_PROXY_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "edge-gateway", about = "Unprivileged EdgeRoute gateway")]
struct Cli {
    #[arg(long, env = "EDGE_GATEWAY_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, env = "EDGE_GATEWAY_BIND", default_value = DEFAULT_BIND)]
    bind: SocketAddr,

    #[arg(long, env = "EDGE_AGENT_SOCKET", default_value = DEFAULT_AGENT_SOCKET)]
    agent_socket: PathBuf,

    #[arg(
        long,
        env = "EDGE_GATEWAY_STATIC_DIR",
        default_value = DEFAULT_STATIC_DIR
    )]
    static_dir: PathBuf,

    #[arg(long, env = "EDGE_GATEWAY_TOKEN")]
    gateway_token: Option<String>,

    #[arg(long, env = "EDGE_API_TOKEN")]
    api_token: Option<String>,
}

#[derive(Clone)]
struct AppState {
    agent_socket: Arc<PathBuf>,
    gateway_token: Option<Arc<str>>,
    api_token: Option<Arc<str>>,
    client: UnixClient,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct GatewayStatus {
    status: &'static str,
    agent_socket: String,
    upstream_auth: &'static str,
    api_auth: &'static str,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    gateway_token: Option<String>,
    api_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    reject_public_bind(cli.bind)?;
    let tokens = load_tokens(cli.config.as_deref(), cli.gateway_token, cli.api_token)?;

    let agent_socket = Arc::new(cli.agent_socket);
    let state = AppState {
        agent_socket: Arc::clone(&agent_socket),
        gateway_token: tokens.gateway_token.map(Arc::from),
        api_token: tokens.api_token.map(Arc::from),
        client: Client::builder(TokioExecutor::new()).build(UnixConnector {
            socket_path: agent_socket,
        }),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/dashboard", get(index))
        .route("/mappings", get(index))
        .route("/tools", get(index))
        .route("/topology", get(index))
        .route("/oracle", get(index))
        .route("/reconcile", get(index))
        .route("/netbird", get(index))
        .route("/logs", get(index))
        .route("/healthz", get(health))
        .route("/status", get(status))
        .route("/api/{*path}", any(proxy))
        .route("/ui/dashboard", get(ui::dashboard))
        .route("/ui/mappings", get(ui::mappings).post(ui::create_mapping))
        .route("/ui/mappings/{id}/enable", post(ui::enable_mapping))
        .route("/ui/mappings/{id}/disable", post(ui::disable_mapping))
        .route("/ui/mappings/{id}", delete(ui::delete_mapping))
        .route("/ui/reconcile", get(ui::reconcile).post(ui::run_reconcile))
        .route("/ui/reconcile/dry-run", post(ui::dry_run_ruleset))
        .route("/ui/tools", get(ui::tools))
        .route("/ui/tools/ping", post(ui::ping_tool))
        .route("/ui/tools/port-test", post(ui::port_test_tool))
        .route("/ui/tools/tcpdump", post(ui::tcpdump_tool))
        .route("/ui/tools/dry-run", post(ui::tools_dry_run))
        .route("/ui/tools/reconcile-check", post(ui::tools_reconcile_check))
        .route("/ui/topology", get(ui::topology))
        .route("/ui/oracle", get(ui::oracle))
        .route("/ui/oracle/allocate", post(ui::oracle_allocate))
        .route("/ui/oracle/release", post(ui::oracle_release))
        .route("/ui/oracle/vnic-check", post(ui::oracle_vnic_check))
        .route("/ui/oracle/public-ips", post(ui::oracle_public_ips))
        .route("/ui/oracle/nsg/add", post(ui::oracle_nsg_add))
        .route("/ui/oracle/nsg/remove", post(ui::oracle_nsg_remove))
        .route("/ui/netbird", get(ui::netbird))
        .route("/ui/events", get(ui::events))
        .route("/ui/logs", get(ui::events))
        .route("/ui/logs/download", get(ui::download_logs))
        .nest_service("/static", ServeDir::new(cli.static_dir))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(cli.bind).await?;
    tracing::info!("edge-gateway listening on {}", cli.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Tokens {
    gateway_token: Option<String>,
    api_token: Option<String>,
}

fn load_tokens(
    config: Option<&FsPath>,
    cli_gateway_token: Option<String>,
    cli_api_token: Option<String>,
) -> Result<Tokens> {
    let file = config.map(load_config).transpose()?;
    let gateway_token = cli_gateway_token.or_else(|| {
        file.as_ref()
            .and_then(|config| config.gateway_token.clone())
    });
    let api_token = cli_api_token.or_else(|| file.and_then(|config| config.api_token));
    if gateway_token.as_deref() == Some("") {
        return Err(anyhow!("gateway token must not be empty"));
    }
    if api_token.as_deref() == Some("") {
        return Err(anyhow!("upstream API token must not be empty"));
    }
    #[cfg(not(feature = "mock"))]
    if api_token.is_none() {
        return Err(anyhow!(
            "missing upstream API token; set EDGE_API_TOKEN or config api_token"
        ));
    }
    Ok(Tokens {
        gateway_token,
        api_token,
    })
}

fn load_config(path: &FsPath) -> Result<FileConfig> {
    let raw = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&raw)?)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../../web/edgeroute-ui/index.html"))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(State(state): State<AppState>) -> Json<GatewayStatus> {
    Json(GatewayStatus {
        status: "ok",
        agent_socket: state.agent_socket.display().to_string(),
        upstream_auth: if state.api_token.is_some() {
            "configured"
        } else {
            "unconfigured"
        },
        api_auth: if state.gateway_token.is_some() {
            "bearer"
        } else {
            "netbird"
        },
    })
}

async fn proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let (parts, body) = request.into_parts();
    require_gateway_auth(&parts.headers, state.gateway_token.as_ref())?;
    let body = to_bytes(body, MAX_PROXY_BODY_BYTES)
        .await
        .map_err(GatewayError::bad_gateway)?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let upstream_path = strip_api_prefix(path_and_query, &path);
    let (status, headers, body) = agent::send_raw(
        &state,
        parts.method.clone(),
        upstream_path,
        parts.headers,
        body,
    )
    .await?;
    let mut builder = Response::builder().status(status);
    for (name, value) in headers
        .iter()
        .filter(|(name, _)| !hop_by_hop_headers().contains(name))
    {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(body))
        .map_err(GatewayError::internal)
}

fn require_gateway_auth(headers: &HeaderMap, token: Option<&Arc<str>>) -> Result<(), GatewayError> {
    let Some(expected) = token else {
        return Ok(());
    };
    let Some(actual) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(GatewayError::unauthorized());
    };
    if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(GatewayError::unauthorized())
    }
}

fn strip_api_prefix<'a>(path_and_query: &'a str, matched_path: &str) -> &'a str {
    if matched_path.is_empty() {
        "/"
    } else {
        path_and_query
            .strip_prefix("/api")
            .unwrap_or(path_and_query)
    }
}

fn upstream_uri(path_and_query: &str) -> Result<Uri, GatewayError> {
    let path = if path_and_query.starts_with('/') {
        path_and_query.to_owned()
    } else {
        format!("/{path_and_query}")
    };
    format!("http://edge-agent{path}")
        .parse()
        .map_err(GatewayError::internal)
}

fn rewrite_headers(headers: &mut HeaderMap, token: &str) -> Result<(), GatewayError> {
    let connection_nominated = connection_nominated_headers(headers);
    for header in hop_by_hop_headers() {
        headers.remove(header);
    }
    for header in connection_nominated {
        headers.remove(header);
    }
    headers.remove(AUTHORIZATION);
    headers.insert(HOST, HeaderValue::from_static("edge-agent"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(GatewayError::internal)?,
    );
    Ok(())
}

fn connection_nominated_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect()
}

fn hop_by_hop_headers() -> [HeaderName; 8] {
    [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-authenticate"),
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("te"),
        HeaderName::from_static("trailer"),
        TRANSFER_ENCODING,
        HeaderName::from_static("upgrade"),
    ]
}

fn reject_public_bind(addr: SocketAddr) -> Result<()> {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            anyhow::bail!("refusing to bind gateway to wildcard address {addr}")
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            anyhow::bail!("refusing to bind gateway to wildcard address {addr}")
        }
        _ => Ok(()),
    }
}

#[derive(Debug)]
struct GatewayError {
    status: StatusCode,
    message: String,
}

impl GatewayError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "missing or invalid bearer token".to_owned(),
        }
    }

    fn bad_gateway(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: error.to_string(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max {
        let a = left.get(idx).copied().unwrap_or(0);
        let b = right.get(idx).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response<Body> {
        (self.status, self.message).into_response()
    }
}

#[derive(Clone)]
struct UnixConnector {
    socket_path: Arc<PathBuf>,
}

impl Service<Uri> for UnixConnector {
    type Response = TokioIo<AgentStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let path = Arc::clone(&self.socket_path);
        Box::pin(async move {
            UnixStream::connect(path.as_ref())
                .await
                .map(AgentStream)
                .map(TokioIo::new)
        })
    }
}

struct AgentStream(UnixStream);

impl tokio::io::AsyncRead for AgentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AgentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for AgentStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_wildcard_bind() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();

        assert!(reject_public_bind(addr).is_err());
    }

    #[test]
    fn builds_upstream_uri_without_api_prefix() {
        let uri = upstream_uri("/v1/status?full=true").unwrap();

        assert_eq!(uri.to_string(), "http://edge-agent/v1/status?full=true");
    }

    #[test]
    fn strips_api_prefix_before_proxying() {
        assert_eq!(
            strip_api_prefix("/api/v1/status", "v1/status"),
            "/v1/status"
        );
        assert_eq!(
            strip_api_prefix("/api/v1/status?full=true", "v1/status"),
            "/v1/status?full=true"
        );
    }

    #[test]
    fn loads_optional_gateway_token() {
        let tokens = load_tokens(None, None, Some("upstream".to_owned())).unwrap();

        assert_eq!(tokens.gateway_token, None);
        assert_eq!(tokens.api_token.as_deref(), Some("upstream"));
    }

    #[cfg(feature = "mock")]
    #[test]
    fn mock_feature_allows_missing_upstream_token() {
        let tokens = load_tokens(None, None, None).unwrap();

        assert_eq!(tokens.api_token, None);
    }

    #[test]
    fn rewrites_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token"),
        );
        headers.insert(
            HeaderName::from_static("x-remove-me"),
            HeaderValue::from_static("value"),
        );
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade, x-remove-me"));

        rewrite_headers(&mut headers, "upstream-token").unwrap();

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer upstream-token");
        assert!(headers.get(CONNECTION).is_none());
        assert!(headers.get(TRANSFER_ENCODING).is_none());
        assert!(headers.get("x-remove-me").is_none());
    }

    #[test]
    fn optional_gateway_authorization() {
        let mut headers = HeaderMap::new();
        assert!(require_gateway_auth(&headers, None).is_ok());
        let token: Arc<str> = Arc::from("gateway-token");
        assert!(require_gateway_auth(&headers, Some(&token)).is_err());

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong-token"),
        );
        assert!(require_gateway_auth(&headers, Some(&token)).is_err());

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer gateway-token"),
        );
        assert!(require_gateway_auth(&headers, Some(&token)).is_ok());
    }

    #[test]
    fn compares_tokens_constant_time_style() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrex"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
    }
}
