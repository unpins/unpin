use std::env;

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
    let resp = minreq::get(url)
        .with_header("User-Agent", USER_AGENT)
        .send()
        .map_err(|e| format!("download {url}: {e}"))?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(format!("HTTP {} downloading {url}", resp.status_code));
    }
    Ok(resp.into_bytes())
}
