use std::env;
use std::fmt::Write as FmtWrite;
use std::io::{self, IsTerminal, Read, Write};
use std::time::{Duration, Instant};

use nanoserde::DeJson;

const USER_AGENT: &str = concat!("ghp/", env!("CARGO_PKG_VERSION"));

#[derive(DeJson, Debug)]
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

fn api_get(url: &str) -> Result<String, String> {
    let mut req = minreq::get(url)
        .with_header("User-Agent", USER_AGENT)
        .with_header("Accept", "application/vnd.github+json");
    if let Ok(token) = env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            req = req.with_header("Authorization", format!("Bearer {token}"));
        }
    }
    let resp = req.send().map_err(|e| format!("HTTP GET {url}: {e}"))?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(format!(
            "HTTP {} for {url}: {}",
            resp.status_code,
            resp.as_str().unwrap_or("")
        ));
    }
    resp.as_str()
        .map(|s| s.to_owned())
        .map_err(|e| format!("decode body for {url}: {e}"))
}

pub fn download(url: &str) -> Result<Vec<u8>, String> {
    let mut resp = minreq::get(url)
        .with_header("User-Agent", USER_AGENT)
        .send_lazy()
        .map_err(|e| format!("download {url}: {e}"))?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(format!("HTTP {} downloading {url}", resp.status_code));
    }
    let total = resp
        .headers
        .get("content-length")
        .and_then(|s| s.parse::<u64>().ok());

    let interactive = io::stderr().is_terminal();
    let mut buf: Vec<u8> = Vec::with_capacity(total.unwrap_or(0) as usize);
    let mut chunk = [0u8; 32 * 1024];
    let start = Instant::now();
    let mut last_render = start - Duration::from_millis(100);

    loop {
        let n = resp
            .read(&mut chunk)
            .map_err(|e| format!("read {url}: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        if interactive && last_render.elapsed() >= Duration::from_millis(80) {
            render_progress(buf.len() as u64, total, start);
            last_render = Instant::now();
        }
    }

    if interactive {
        render_progress(buf.len() as u64, total, start);
        let _ = writeln!(io::stderr().lock());
    }

    Ok(buf)
}

fn render_progress(done: u64, total: Option<u64>, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let rate = (done as f64 / elapsed) as u64;
    let mut line = String::with_capacity(96);
    if let Some(t) = total {
        let pct = (done as f64 / t as f64 * 100.0).clamp(0.0, 100.0);
        let width = 30usize;
        let filled = ((pct / 100.0) * width as f64) as usize;
        line.push('[');
        for _ in 0..filled {
            line.push('#');
        }
        for _ in filled..width {
            line.push('-');
        }
        line.push(']');
        let _ = write!(
            line,
            " {:>3.0}%  {} / {}  {}/s",
            pct,
            human_bytes(done),
            human_bytes(t),
            human_bytes(rate),
        );
    } else {
        let _ = write!(line, "  {}  {}/s", human_bytes(done), human_bytes(rate));
    }
    let mut err = io::stderr().lock();
    let _ = write!(err, "\r{:<78}", line);
    let _ = err.flush();
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
