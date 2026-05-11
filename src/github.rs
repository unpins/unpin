use std::env;
use std::io::{self, Read};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use nanoserde::DeJson;

use crate::http;

const USER_AGENT: &str = concat!("unpin/", env!("CARGO_PKG_VERSION"));

#[derive(DeJson, Debug, Clone)]
pub struct Release {
    pub tag_name: String,
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

fn auth_header() -> Option<String> {
    env::var("GITHUB_TOKEN").ok().and_then(|t| {
        if t.is_empty() {
            None
        } else {
            Some(format!("Bearer {t}"))
        }
    })
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
        let body_str = std::str::from_utf8(&resp.body).unwrap_or("");
        return Err(format!("HTTP {} for {url}: {body_str}", resp.status));
    }
    String::from_utf8(resp.body).map_err(|e| format!("decode body for {url}: {e}"))
}

/// Convenience download into memory. Used for small payloads (checksum files).
/// Renders no progress.
pub fn download(url: &str) -> Result<Vec<u8>, String> {
    let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::hidden());
    let mut buf = Vec::new();
    let mut reader = download_stream_into(url, bar)?;
    std::io::copy(&mut reader, &mut buf).map_err(|e| format!("read {url}: {e}"))?;
    Ok(buf)
}

/// Streaming download wired to an indicatif `ProgressBar`. Sets the bar's
/// style and length here so the caller only has to attach it to a
/// `MultiProgress` and (optionally) set a prefix.
pub fn download_stream_into(url: &str, bar: ProgressBar) -> Result<ProgressStream, String> {
    let client = http::default_client();
    let headers: Vec<(&str, &str)> = vec![("User-Agent", USER_AGENT)];
    let stream = client.get_streaming(url, &headers)?;
    if stream.status() < 200 || stream.status() >= 300 {
        return Err(format!("HTTP {} downloading {url}", stream.status()));
    }
    match stream.content_length() {
        Some(total) => {
            bar.set_length(total);
            bar.set_style(download_progress_style());
        }
        None => {
            bar.set_style(download_progress_style_unknown());
            bar.enable_steady_tick(std::time::Duration::from_millis(120));
        }
    }
    Ok(ProgressStream { inner: stream, bar })
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

impl Drop for ProgressStream {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
    }
}

/// Standard progress style for downloads: thin parallelogram bar.
/// `prefix` should be set per-bar to identify the package (e.g. `"ripgrep 14.1"`).
pub fn download_progress_style() -> ProgressStyle {
    // `progress_chars("▰▰▱")`: fill, transition (same glyph → no sub-cell), empty.
    ProgressStyle::with_template(
        "  {prefix:<16.cyan} {bar:14.green/blue} {percent:>3}%  {bytes:>9}/{total_bytes:<9}  {bytes_per_sec:>10}",
    )
    .unwrap()
    .progress_chars("▰▰▱")
}

/// Style used when `Content-Length` was not provided. Spinner + bytes + rate, no bar.
pub fn download_progress_style_unknown() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {prefix:<16.cyan} {spinner} {bytes:>9}  {bytes_per_sec:>10}",
    )
    .unwrap()
}
