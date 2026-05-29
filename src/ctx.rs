//! Per-invocation context: parsed config + pre-resolved auth header + HTTP
//! client (with timeout baked in) + verbose flag. Built once at the top of
//! each command in `main`, then borrowed (`&Ctx`) down the call tree.
//!
//! Sync because workers in [`crate::install::parallel_extract`] share the
//! same `&Ctx` across threads. `Box<dyn HttpClient>` is Sync via the trait's
//! `Send + Sync` bound; the other fields are Sync by virtue of their types.

use std::env;

use crate::config::Config;
use crate::http::{self, HttpClient};
use crate::platform::Paths;

pub struct Ctx {
    pub cfg: Config,
    pub http: Box<dyn HttpClient>,
    pub auth: Option<String>,
    pub verbose: bool,
    /// On-disk layout, resolved once in `main` and threaded in here so the
    /// network commands (and the extract workers that share `&Ctx`) reach it
    /// without a separate parameter. Local-only commands carry `&Paths`
    /// directly instead.
    pub paths: Paths,
}

impl Ctx {
    /// Load config, resolve auth, build HTTP client with the configured
    /// timeout. Only called for commands that hit GitHub (install, update,
    /// run, info) — local-only commands (list, remove, prune, completion)
    /// skip this so they don't pay for `gh auth token` shell-out etc.
    pub fn new(verbose: bool, paths: Paths) -> Self {
        let cfg = Config::load(&paths.config);
        let http = http::default_client(cfg.http_timeout());
        let auth = resolve_auth_header(&cfg);
        Self {
            cfg,
            http,
            auth,
            verbose,
            paths,
        }
    }
}

/// Resolved once per command (during [`Ctx::new`]). Order:
/// 1. `GITHUB_TOKEN` — universal CI/tooling convention (set by GitHub Actions).
/// 2. `GH_TOKEN` (what the `gh` CLI itself reads).
/// 3. `gh auth token` — **opt-in** via `use_gh_auth = true` in the config
///    file. Disabled by default because the token stored by `gh auth login`
///    carries the full set of scopes the user granted at login time (often
///    `repo` + `workflow`), which is far broader than what unpin actually
///    needs (read-only release metadata). Matching the security-conservative
///    majority (eget, ubi, cargo-binstall) instead of aqua/mise's silent
///    shell-out.
///
/// Authenticated requests raise the API rate limit from 60/hour (anonymous,
/// by IP) to 5000/hour (per user).
fn resolve_auth_header(cfg: &Config) -> Option<String> {
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(token) = env::var(var)
            && !token.is_empty()
        {
            return Some(format!("Bearer {token}"));
        }
    }
    if !cfg.use_gh_auth() {
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
