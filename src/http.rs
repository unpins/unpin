use std::io::Read;

/// Headers as borrowed key-value pairs. Keys are case-insensitive at the wire
/// level; backends should preserve the casing given here.
pub type Headers<'a> = &'a [(&'a str, &'a str)];

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Streaming HTTP response. Reading consumes the body.
pub trait HttpStream: Read {
    fn status(&self) -> u16;
    fn content_length(&self) -> Option<u64>;
}

/// Hard cap on bodies buffered by [`HttpClient::get`]. GitHub release JSON is
/// tens of KB in practice (≈200 KB even for a release with ~100 assets); this
/// is a generous bound whose only job is to stop a compromised or MITM'd API
/// endpoint (redirects are followed, so the final host isn't necessarily
/// api.github.com) from streaming unbounded data into memory before the parser
/// ever sees it. The streaming path ([`HttpClient::get_streaming`]) is capped
/// separately by its callers.
pub const GET_BODY_CAP_BYTES: u64 = 8 * 1024 * 1024;

/// Minimum surface unpin needs from an HTTP client.
///
/// Contract:
/// - GET only.
/// - Follows redirects (302/301/307/308) up to a reasonable cap. GitHub's
///   `browser_download_url` always 302s to objects.githubusercontent.com.
/// - Returns the response as-is (no error mapping on non-2xx). Callers decide.
/// - `get` buffers the body, bounded by [`GET_BODY_CAP_BYTES`] (errors past
///   it); suitable for JSON API responses.
/// - `get_streaming` does not buffer; suitable for release-asset downloads.
///
/// `Send + Sync` so a single client built in `Ctx` can be shared with workers
/// in `parallel_extract`.
pub trait HttpClient: Send + Sync {
    fn get(&self, url: &str, headers: Headers) -> Result<HttpResponse, String>;
    fn get_streaming(
        &self,
        url: &str,
        headers: Headers,
    ) -> Result<Box<dyn HttpStream + Send>, String>;
}

/// Build the default HTTP client with a timeout (in seconds) baked in. The
/// timeout covers connect + read; minreq applies it to both
/// `TcpStream::connect_timeout` and the underlying socket's read-timeout.
/// Without it, a stuck TCP handshake to api.github.com hangs indefinitely on
/// `Resolving...`.
pub fn default_client(timeout_secs: u64) -> Box<dyn HttpClient> {
    Box::new(minreq_backend::MinreqClient { timeout_secs })
}

mod minreq_backend {
    use super::*;

    pub struct MinreqClient {
        pub(super) timeout_secs: u64,
    }

    impl HttpClient for MinreqClient {
        fn get(&self, url: &str, headers: Headers) -> Result<HttpResponse, String> {
            let mut req = minreq::get(url).with_timeout(self.timeout_secs);
            for (k, v) in headers {
                req = req.with_header(*k, *v);
            }
            // `send_lazy` + a capped read instead of `send().into_bytes()`:
            // the latter buffers the entire body unconditionally, so a
            // malicious/MITM'd endpoint could exhaust memory before we ever
            // look at it. Read at most CAP+1 bytes so an exactly-CAP body
            // still passes while anything larger trips the overflow check.
            let resp = req
                .send_lazy()
                .map_err(|e| format!("HTTP GET {url}: {e}"))?;
            let status = resp.status_code as u16;
            let mut body = Vec::new();
            Read::take(resp, GET_BODY_CAP_BYTES + 1)
                .read_to_end(&mut body)
                .map_err(|e| format!("HTTP GET {url}: {e}"))?;
            if body.len() as u64 > GET_BODY_CAP_BYTES {
                return Err(format!(
                    "response exceeded {GET_BODY_CAP_BYTES}-byte cap for {url}"
                ));
            }
            Ok(HttpResponse { status, body })
        }

        fn get_streaming(
            &self,
            url: &str,
            headers: Headers,
        ) -> Result<Box<dyn HttpStream + Send>, String> {
            let mut req = minreq::get(url).with_timeout(self.timeout_secs);
            for (k, v) in headers {
                req = req.with_header(*k, *v);
            }
            let resp = req
                .send_lazy()
                .map_err(|e| format!("HTTP GET {url}: {e}"))?;
            let content_length = resp
                .headers
                .get("content-length")
                .and_then(|s| s.parse::<u64>().ok());
            let status = resp.status_code as u16;
            Ok(Box::new(MinreqStream {
                status,
                content_length,
                inner: resp,
            }))
        }
    }

    struct MinreqStream {
        status: u16,
        content_length: Option<u64>,
        inner: minreq::ResponseLazy,
    }

    impl Read for MinreqStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl HttpStream for MinreqStream {
        fn status(&self) -> u16 {
            self.status
        }
        fn content_length(&self) -> Option<u64> {
            self.content_length
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Spin up a one-shot loopback server that replies 200 with a body of
    /// `body_len` bytes. Returns the port. Write errors are swallowed so the
    /// over-cap test can hang up early without panicking the server thread.
    fn serve_once(body_len: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Read (and discard) the request headers so the client's
                // write side doesn't block on a full socket buffer.
                let mut scratch = [0u8; 2048];
                let _ = sock.read(&mut scratch);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                );
                if sock.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let chunk = vec![b'x'; 64 * 1024];
                let mut sent = 0;
                while sent < body_len {
                    let n = (body_len - sent).min(chunk.len());
                    if sock.write_all(&chunk[..n]).is_err() {
                        break; // client hung up after hitting the cap
                    }
                    sent += n;
                }
            }
        });
        port
    }

    #[test]
    fn get_rejects_body_over_cap() {
        let port = serve_once((GET_BODY_CAP_BYTES + 64 * 1024) as usize);
        let client = default_client(30);
        let err = client
            .get(&format!("http://127.0.0.1:{port}/"), &[])
            .unwrap_err();
        assert!(err.contains("exceeded"), "expected cap error, got: {err}");
    }

    #[test]
    fn get_accepts_body_within_cap() {
        let port = serve_once(1024);
        let client = default_client(30);
        let resp = client
            .get(&format!("http://127.0.0.1:{port}/"), &[])
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.len(), 1024);
    }
}
