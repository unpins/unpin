use std::env;
use std::io::{self, Read};
use std::sync::OnceLock;

use indicatif::{ProgressBar, ProgressStyle};
use nanoserde::DeJson;

use crate::http;

const USER_AGENT: &str = concat!("unpin/", env!("CARGO_PKG_VERSION"));

#[derive(DeJson, Debug, Clone)]
pub struct Release {
    pub tag_name: String,
    #[nserde(default)]
    pub published_at: String,
    #[nserde(default)]
    pub assets: Vec<Asset>,
}

#[derive(DeJson, Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

pub fn fetch_latest(repo: &str) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    fetch_release(&url)
}

pub fn fetch_tag(repo: &str, tag: &str) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    fetch_release(&url)
}

fn fetch_release(url: &str) -> Result<Release, String> {
    let body = api_get(url)?;
    DeJson::deserialize_json(&body).map_err(|e| format!("parse release JSON: {e}"))
}

/// Resolved once per process. Order:
/// 1. `UNPIN_GITHUB_TOKEN` — tool-scoped, lets users hand unpin a narrow PAT
///    (e.g. `public_repo`-only) without overriding `GITHUB_TOKEN` globally.
/// 2. `GITHUB_TOKEN`
/// 3. `GH_TOKEN` (what the `gh` CLI itself reads)
/// 4. `gh auth token` — **opt-in** via `UNPIN_USE_GH_AUTH=1`. Disabled by
///    default because the token stored by `gh auth login` carries the full
///    set of scopes the user granted at login time (often `repo` + `workflow`),
///    which is far broader than what unpin actually needs (read-only release
///    metadata). Matching the security-conservative majority (eget, ubi,
///    cargo-binstall) instead of aqua/mise's silent shell-out.
///
/// Authenticated requests raise the API rate limit from 60/hour (anonymous,
/// by IP) to 5000/hour (per user).
fn auth_header() -> Option<String> {
    static AUTH_HEADER: OnceLock<Option<String>> = OnceLock::new();
    AUTH_HEADER.get_or_init(resolve_auth_header).clone()
}

fn resolve_auth_header() -> Option<String> {
    for var in ["UNPIN_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(t) = env::var(var)
            && !t.is_empty()
        {
            return Some(format!("Bearer {t}"));
        }
    }
    if env::var("UNPIN_USE_GH_AUTH").ok().as_deref() != Some("1") {
        return None;
    }
    let output = std::process::Command::new("gh")
        .args(["auth", "token"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let token = std::str::from_utf8(&output.stdout).ok()?.trim();
    if token.is_empty() {
        return None;
    }
    Some(format!("Bearer {token}"))
}

fn api_get(url: &str) -> Result<String, String> {
    let client = http::default_client();
    let auth = auth_header();
    let mut headers: Vec<(&str, &str)> = vec![
        ("User-Agent", USER_AGENT),
        ("Accept", "application/vnd.github+json"),
    ];
    if let Some(ref h) = auth {
        headers.push(("Authorization", h));
    }
    let resp = client.get(url, &headers)?;
    if resp.status < 200 || resp.status >= 300 {
        if resp.status == 404 {
            return Err("not found (check package name or version)".into());
        }
        let msg = github_error_message(&resp.body)
            .unwrap_or_else(|| "request failed".to_string());
        return Err(format!("HTTP {}: {msg}", resp.status));
    }
    String::from_utf8(resp.body).map_err(|e| format!("decode body for {url}: {e}"))
}

#[derive(DeJson)]
struct ErrorBody {
    message: String,
}

fn github_error_message(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    DeJson::deserialize_json(s).ok().map(|e: ErrorBody| e.message)
}

/// Convenience download into memory. Used for small payloads (checksum files).
/// Renders no progress.
pub fn download(url: &str) -> Result<Vec<u8>, String> {
    let bar = ProgressBar::hidden();
    let mut buf = Vec::new();
    let mut reader = download_stream_into(url, &bar)?;
    std::io::copy(&mut reader, &mut buf).map_err(|e| format!("read {url}: {e}"))?;
    Ok(buf)
}

/// Streaming download against a caller-provided `ProgressBar`. The bar must
/// already be registered with a `MultiProgress` (or hidden) before this is
/// called — otherwise indicatif draws standalone stderr lines that stay in
/// scrollback when the bar is later attached, producing ghost rows.
///
/// Once the HTTP response is in, this only sets the length (or, in the rare
/// `Content-Length`-missing case, swaps to a spinner style). The style itself
/// is whatever the caller pre-configured.
pub fn download_stream_into(url: &str, bar: &ProgressBar) -> Result<ProgressStream, String> {
    let client = http::default_client();
    let headers: Vec<(&str, &str)> = vec![("User-Agent", USER_AGENT)];
    let stream = client.get_streaming(url, &headers)?;
    if stream.status() < 200 || stream.status() >= 300 {
        return Err(format!("HTTP {} downloading {url}", stream.status()));
    }
    match stream.content_length() {
        Some(total) => bar.set_length(total),
        None => {
            bar.set_style(download_progress_style_unknown());
            bar.enable_steady_tick(std::time::Duration::from_millis(120));
        }
    }
    Ok(ProgressStream {
        inner: stream,
        bar: bar.clone(),
    })
}

pub struct ProgressStream {
    inner: Box<dyn http::HttpStream + Send>,
    bar: ProgressBar,
}

impl Read for ProgressStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.bar.inc(n as u64);
        }
        Ok(n)
    }
}

// No Drop impl: the caller decides the bar's final state (clear on success,
// or swap to error style + abandon on failure). Hidden bars (used by
// `download()`) don't need explicit clearing.

/// Standard progress style for downloads: thin parallelogram bar.
/// Callers should pad `prefix` themselves so name/tag align across bars.
pub fn download_progress_style() -> ProgressStyle {
    // `progress_chars("▰▰▱")`: fill, transition (same glyph → no sub-cell), empty.
    ProgressStyle::with_template(
        "  {prefix:.cyan}  {bar:14.green/blue} {percent:>3}%  {bytes:>9}/{total_bytes:<9}  {bytes_per_sec:>10}",
    )
    .unwrap()
    .progress_chars("▰▰▱")
}

/// Style used when `Content-Length` was not provided. Spinner + bytes + rate, no bar.
pub fn download_progress_style_unknown() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {prefix:.cyan}  {spinner} {bytes:>9}  {bytes_per_sec:>10}",
    )
    .unwrap()
}

/// Style for a failed download: prefix + red bar (frozen at the failure point)
/// + the error reason in red. Caller sets the reason via `bar.set_message(...)`.
pub fn download_error_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {prefix:.red}  {bar:14.red/red} {percent:>3}%  {wide_msg:.red}",
    )
    .unwrap()
    .progress_chars("▰▰▱")
}
