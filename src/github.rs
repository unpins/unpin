use std::io::{self, Read};
use std::sync::Arc;

use nanoserde::DeJson;

use crate::ctx::Ctx;

/// Sink for streaming-download byte progress. Decouples [`download_stream_into`]
/// from the UI: the live progress thread backs this with shared atomics
/// (`progress::RowBytes`), while non-UI callers (`download`) use [`NoopSink`].
pub trait ByteSink: Send + Sync {
    /// Pre-seeded total hint (e.g. `Asset.size`), or 0 when none is known.
    fn hint(&self) -> u64;
    /// Set the authoritative total once `Content-Length` is in.
    fn set_total(&self, total: u64);
    /// Mark the total unknown (no header *and* no hint) → spinner mode.
    fn set_unknown(&self);
    /// Account `n` freshly-read bytes.
    fn add(&self, n: u64);
    /// Total bytes read so far (used for the truncation check).
    fn loaded(&self) -> u64;
}

/// Discards all progress — for the buffered, non-streaming [`download`] path.
pub struct NoopSink;
impl ByteSink for NoopSink {
    fn hint(&self) -> u64 {
        0
    }
    fn set_total(&self, _total: u64) {}
    fn set_unknown(&self) {}
    fn add(&self, _n: u64) {}
    fn loaded(&self) -> u64 {
        0
    }
}

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
    /// Size in bytes as reported by the GitHub API. `0` when missing from the
    /// response (older responses sometimes elide it). Used both for the asset
    /// picker's human size column and as a fallback for the progress bar
    /// length when the CDN doesn't return Content-Length.
    #[nserde(default)]
    pub size: u64,
}

pub fn fetch_latest(ctx: &Ctx, repo: &str) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    fetch_release_url(ctx, &url)
}

pub fn fetch_tag(ctx: &Ctx, repo: &str, tag: &str) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    fetch_release_url(ctx, &url)
}

fn fetch_release_url(ctx: &Ctx, url: &str) -> Result<Release, String> {
    let body = api_get(ctx, url)?;
    DeJson::deserialize_json(&body).map_err(|e| format!("parse release JSON: {e}"))
}

fn api_get(ctx: &Ctx, url: &str) -> Result<String, String> {
    let mut headers: Vec<(&str, &str)> = vec![
        ("User-Agent", USER_AGENT),
        ("Accept", "application/vnd.github+json"),
    ];
    if let Some(ref h) = ctx.auth {
        headers.push(("Authorization", h));
    }
    if ctx.verbose {
        eprintln!("  GET {url}");
    }
    let resp = ctx.http.get(url, &headers)?;
    if ctx.verbose {
        eprintln!("  -> HTTP {}", resp.status);
    }
    if resp.status < 200 || resp.status >= 300 {
        if resp.status == 404 {
            return Err("not found (check package name or version)".into());
        }
        let msg = github_error_message(&resp.body).unwrap_or_else(|| "request failed".to_string());
        let mut out = format!("HTTP {}: {msg}", resp.status);
        // A 403/429 on an unauthenticated request is almost always the 60/hour
        // anonymous API rate limit. GitHub's own message ("API rate limit
        // exceeded…") never mentions that unpin reads a token, so the user has
        // no actionable next step — point them at the env var that lifts the
        // cap. When auth IS present a 403 means something else (bad/insufficient
        // token), and GitHub's message already explains it, so skip the hint.
        if matches!(resp.status, 403 | 429) && ctx.auth.is_none() {
            out.push_str(
                "\nhint: anonymous GitHub API requests are limited to 60/hour. \
                 Set GITHUB_TOKEN (or GH_TOKEN), or use_gh_auth = true in config, \
                 to raise the limit to 5000/hour.",
            );
        }
        return Err(out);
    }
    String::from_utf8(resp.body).map_err(|e| format!("decode body for {url}: {e}"))
}

#[derive(DeJson)]
struct ErrorBody {
    message: String,
}

fn github_error_message(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    DeJson::deserialize_json(s)
        .ok()
        .map(|e: ErrorBody| e.message)
}

/// Hard cap on bodies read by [`download`]. Used for checksum files (tens of
/// bytes in practice). A malicious or misbehaving server could otherwise send
/// gigabytes and exhaust memory before the body even reaches the parser.
const DOWNLOAD_CAP_BYTES: u64 = 64 * 1024;

/// Convenience download into memory. Used for small payloads (checksum files).
/// Renders no progress. Called only from the serial preflight phase, so a raw
/// `eprintln!` for the verbose URL log is safe (no `MultiProgress` rendering
/// to race against).
///
/// Bodies are capped at [`DOWNLOAD_CAP_BYTES`] — if a server returns more, the
/// call fails rather than buffering an unbounded response. Callers fetching
/// large payloads (release assets) should go through [`download_stream_into`].
pub fn download(ctx: &Ctx, url: &str) -> Result<Vec<u8>, String> {
    if ctx.verbose {
        eprintln!("  GET {url}");
    }
    let mut buf = Vec::new();
    let reader = download_stream_into(ctx, url, Arc::new(NoopSink))?;
    // take(N+1) so we can detect the "exceeded the cap" case: if the cap fits
    // exactly, take(N) would also succeed and we'd miss the overflow.
    let mut capped = reader.take(DOWNLOAD_CAP_BYTES + 1);
    std::io::copy(&mut capped, &mut buf).map_err(|e| format!("read {url}: {e}"))?;
    if buf.len() as u64 > DOWNLOAD_CAP_BYTES {
        return Err(format!(
            "response exceeded {DOWNLOAD_CAP_BYTES}-byte cap for {url}"
        ));
    }
    Ok(buf)
}

/// Streaming download reporting byte progress to a caller-provided [`ByteSink`].
///
/// Once the HTTP response is in, this only resolves the total: the server's
/// `Content-Length` wins; absent that, a pre-seeded hint (`Asset.size`) is
/// kept; absent both, the sink is flagged unknown (the UI shows a spinner
/// instead of a bar).
pub fn download_stream_into(
    ctx: &Ctx,
    url: &str,
    sink: Arc<dyn ByteSink>,
) -> Result<ProgressStream, String> {
    let headers: Vec<(&str, &str)> = vec![("User-Agent", USER_AGENT)];
    // Verbose URL printing happens at the call site — it has the right
    // serialization context (`Ui::log` in the parallel-worker path, plain
    // `eprintln!` in serial helpers like `download()`). Logging here would
    // race with the render thread on a TTY.
    let stream = ctx.http.get_streaming(url, &headers)?;
    if stream.status() < 200 || stream.status() >= 300 {
        return Err(format!("HTTP {} downloading {url}", stream.status()));
    }
    match (stream.content_length(), sink.hint()) {
        (Some(total), _) => sink.set_total(total),
        // No Content-Length from the server, but the caller pre-seeded a
        // length hint (typically `Asset.size` from the GitHub API). Keep
        // the hint — it's nearly always accurate and gives a real
        // percentage instead of spinner-only progress.
        (None, hint) if hint > 0 => {}
        (None, _) => sink.set_unknown(),
    }
    Ok(ProgressStream {
        inner: stream,
        sink,
    })
}

pub struct ProgressStream {
    inner: Box<dyn crate::http::HttpStream + Send>,
    sink: Arc<dyn ByteSink>,
}

impl ProgressStream {
    /// Server-declared body length, if it provided a Content-Length header.
    /// Capture this *before* wrapping the stream in e.g. a `HashingReader` —
    /// once wrapped, the inner method is no longer reachable.
    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }
}

impl Read for ProgressStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.sink.add(n as u64);
        }
        Ok(n)
    }
}

// No Drop impl: the row's final state (done/skip/fail glyph) is decided by the
// pipeline via the `progress::Reporter`, not here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::http::{Headers, HttpClient, HttpResponse, HttpStream};
    use crate::platform::Paths;
    use std::path::PathBuf;

    /// Canned-response client: every `get` returns the same status + body.
    struct FakeClient {
        status: u16,
        body: Vec<u8>,
    }
    impl HttpClient for FakeClient {
        fn get(&self, _url: &str, _headers: Headers) -> Result<HttpResponse, String> {
            Ok(HttpResponse {
                status: self.status,
                body: self.body.clone(),
            })
        }
        fn get_streaming(
            &self,
            _url: &str,
            _headers: Headers,
        ) -> Result<Box<dyn HttpStream + Send>, String> {
            unimplemented!("api_get never streams")
        }
    }

    fn ctx_with(status: u16, body: &str, auth: Option<String>) -> Ctx {
        Ctx {
            cfg: Config::default(),
            http: Box::new(FakeClient {
                status,
                body: body.as_bytes().to_vec(),
            }),
            auth,
            verbose: false,
            paths: Paths {
                data: PathBuf::from("/tmp/d"),
                bin: PathBuf::from("/tmp/b"),
                config: PathBuf::from("/tmp/c"),
            },
        }
    }

    const RATE_LIMIT: &str = r#"{"message":"API rate limit exceeded for 1.2.3.4"}"#;

    #[test]
    fn rate_limit_403_unauthenticated_suggests_a_token() {
        let ctx = ctx_with(403, RATE_LIMIT, None);
        let err = api_get(&ctx, "https://api.github.com/x").unwrap_err();
        assert!(err.contains("403"), "got: {err}");
        assert!(err.contains("GITHUB_TOKEN"), "missing token hint: {err}");
        assert!(
            err.contains("rate limit exceeded"),
            "lost GitHub message: {err}"
        );
    }

    #[test]
    fn rate_limit_403_authenticated_omits_the_hint() {
        // A logged-in user hitting 403 has a different problem (bad/insufficient
        // token); the GITHUB_TOKEN hint would be misleading.
        let ctx = ctx_with(403, RATE_LIMIT, Some("Bearer x".into()));
        let err = api_get(&ctx, "https://api.github.com/x").unwrap_err();
        assert!(
            !err.contains("GITHUB_TOKEN"),
            "unexpected token hint: {err}"
        );
    }

    #[test]
    fn not_found_404_stays_a_plain_message() {
        let ctx = ctx_with(404, r#"{"message":"Not Found"}"#, None);
        let err = api_get(&ctx, "https://api.github.com/x").unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
        assert!(
            !err.contains("GITHUB_TOKEN"),
            "404 shouldn't hint a token: {err}"
        );
    }
}
