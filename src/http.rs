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

/// Latched by [`transport_err`] when any HTTP error text reads like a failed
/// host-name resolution. `main` checks it after a failed command to print the
/// opt-in DNS-fallback hint — errors reach `main` summarized ("N operation(s)
/// failed"), so the detection has to happen here, where every transport error
/// is born. May be set from pump threads; hence atomic.
static DNS_FAILURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether any request this run failed on what looks like name resolution.
pub fn saw_dns_failure() -> bool {
    DNS_FAILURE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Format a transport error, latching [`saw_dns_failure`] when it reads like a
/// failed resolution. Loose on purpose: the hint it gates is hedged ("may be"),
/// so a false positive costs a few harmless lines while a false negative hides
/// the only pointer to the fix. Text is all there is to match on — std throws
/// the numeric EAI code away on unix (`ErrorKind::Uncategorized`, no
/// `raw_os_error`), leaving only its stable message prefix; Windows formats the
/// WSA name-resolution codes into the message (`(os error 1100X)`:
/// HOST_NOT_FOUND/TRY_AGAIN/NO_RECOVERY/NO_DATA).
fn transport_err(url: &str, e: impl std::fmt::Display) -> String {
    let msg = format!("HTTP GET {url}: {e}");
    let dns = msg.contains("failed to lookup address information")
        || ["os error 11001", "os error 11002", "os error 11003", "os error 11004"]
            .iter()
            .any(|c| msg.contains(c));
    if dns {
        DNS_FAILURE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    msg
}

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

/// Build the default HTTP client with a timeout (in seconds) baked in.
///
/// The timeout means different things on the two paths, by design:
/// - [`HttpClient::get`] (buffered JSON) hands it straight to minreq as a
///   total request deadline — fine for small bodies, and it still bounds a
///   stuck TCP handshake that would otherwise hang on `Resolving...`.
/// - [`HttpClient::get_streaming`] (release-asset downloads) reinterprets it as
///   an **inactivity / idle** window, not a total cap. minreq's only timeout is
///   a fixed deadline covering connect + headers + the *entire* body, so a
///   large or bandwidth-throttled download blows it even while bytes are still
///   flowing. The streaming path drops minreq's deadline and enforces the idle
///   window itself (see `minreq_backend`).
pub fn default_client(timeout_secs: u64) -> Box<dyn HttpClient> {
    Box::new(minreq_backend::MinreqClient { timeout_secs })
}

mod minreq_backend {
    use super::*;
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

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
                .map_err(|e| transport_err(url, e))?;
            let status = resp.status_code as u16;
            let mut body = Vec::new();
            Read::take(resp, GET_BODY_CAP_BYTES + 1)
                .read_to_end(&mut body)
                .map_err(|e| transport_err(url, e))?;
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
            PumpStream::spawn(url, headers, Duration::from_secs(self.timeout_secs.max(1)))
        }
    }

    /// First message from the pump thread: the response head, or a connect/send
    /// error. Sent once before any body chunk.
    enum Head {
        Ready(u16, Option<u64>),
        Failed(String),
    }

    /// A streaming response whose body is read on a background **pump** thread
    /// and handed over a channel, so the consumer can enforce an *inactivity*
    /// timeout that minreq's fixed total deadline can't express.
    ///
    /// The pump runs the request with **no** minreq timeout (blocking reads) and
    /// forwards fixed-size chunks. The consumer reads with `recv_timeout(window)`:
    /// steady data — however slow — keeps arriving inside the window, while a
    /// truly silent socket trips the window and surfaces a `TimedOut` error.
    ///
    /// On a stall (or a connect that never answers) the pump thread is left
    /// blocked in the kernel and detached; it unwinds only when the socket
    /// finally closes (the peer's RST/FIN — which a well-behaved CDN sends) or
    /// at process exit. A genuinely black-holed socket (no RST, e.g. a dropped
    /// route or half-open NAT) keeps the thread + its fd parked until the
    /// process ends, and a single batch `install a b c …` against a flaky host
    /// can leak one per stalled asset. We accept that here because interrupting
    /// a blocked read needs the raw socket, which minreq hides; if it ever
    /// bites in practice the fix is a generous *total* backstop timeout (a
    /// multiple of the idle window) to cap a wedged read.
    struct PumpStream {
        body_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
        /// Current chunk being drained and the read cursor into it.
        buf: Vec<u8>,
        pos: usize,
        status: u16,
        content_length: Option<u64>,
        /// Idle window: max time to wait for the next chunk before erroring.
        window: Duration,
    }

    impl PumpStream {
        fn spawn(
            url: &str,
            headers: Headers,
            window: Duration,
        ) -> Result<Box<dyn HttpStream + Send>, String> {
            let owned_url = url.to_string();
            let owned_headers: Vec<(String, String)> = headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let (head_tx, head_rx) = mpsc::channel::<Head>();
            // Bounded so the pump can't race ahead and buffer the whole asset in
            // memory while the consumer extracts; a full buffer just blocks the
            // pump (backpressure), it never looks like a stall to the consumer.
            let (body_tx, body_rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(8);

            thread::spawn(move || {
                // No `with_timeout`: minreq's timeout is a single deadline over
                // connect+headers+body, which a slow-but-steady transfer blows.
                // We bound *inactivity* on the consumer side instead.
                let mut req = minreq::get(&owned_url);
                for (k, v) in &owned_headers {
                    req = req.with_header(k.as_str(), v.as_str());
                }
                let mut resp = match req.send_lazy() {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = head_tx.send(Head::Failed(transport_err(&owned_url, e)));
                        return;
                    }
                };
                let content_length = resp
                    .headers
                    .get("content-length")
                    .and_then(|s| s.parse::<u64>().ok());
                if head_tx
                    .send(Head::Ready(resp.status_code as u16, content_length))
                    .is_err()
                {
                    return; // consumer already gave up (connect-idle timeout)
                }
                // Body pump. A dropped receiver (consumer error/abort) makes
                // `send` fail and ends the loop, dropping `resp` and closing the
                // socket. EOF (`Ok(0)`) drops `body_tx`, which the consumer sees
                // as `Disconnected`.
                //
                // 16 KiB, not a big buffer: minreq fills the whole buffer before
                // returning from one `read`, so the chunk size *is* the byte-
                // counter granularity. A large buffer makes `done` jump in big
                // steps held flat for seconds on a slow link (jumpy rate + jumpy
                // bar), and lengthens the per-read blocking time toward the idle
                // window (a false-stall risk with a small `http_timeout`). 16 KiB
                // ≈ one TLS record — fine-grained progress, negligible overhead.
                let mut chunk = [0u8; 16 * 1024];
                loop {
                    match resp.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if body_tx.send(Ok(chunk[..n].to_vec())).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = body_tx.send(Err(e));
                            break;
                        }
                    }
                }
            });

            match head_rx.recv_timeout(window) {
                Ok(Head::Ready(status, content_length)) => Ok(Box::new(PumpStream {
                    body_rx,
                    buf: Vec::new(),
                    pos: 0,
                    status,
                    content_length,
                    window,
                })),
                Ok(Head::Failed(e)) => Err(e),
                Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                    "HTTP GET {url}: no response within {}s (connection stalled)",
                    window.as_secs()
                )),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Err(format!("HTTP GET {url}: connection closed before response"))
                }
            }
        }
    }

    impl Read for PumpStream {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.buf.len() {
                match self.body_rx.recv_timeout(self.window) {
                    Ok(Ok(chunk)) => {
                        self.buf = chunk;
                        self.pos = 0;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("download stalled: no data for {}s", self.window.as_secs()),
                        ));
                    }
                    // Pump finished and dropped its sender → end of body.
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                }
            }
            let remaining = &self.buf[self.pos..];
            let n = remaining.len().min(out.len());
            out[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl HttpStream for PumpStream {
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
    use std::io;
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

    #[test]
    fn streaming_reads_the_whole_body() {
        // 200 KiB exercises several 64 KiB pump chunks crossing the channel.
        let body = 200 * 1024;
        let port = serve_once(body);
        let client = default_client(30);
        let mut stream = client
            .get_streaming(&format!("http://127.0.0.1:{port}/"), &[])
            .unwrap();
        assert_eq!(stream.status(), 200);
        assert_eq!(stream.content_length(), Some(body as u64));
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), body);
        assert!(buf.iter().all(|&b| b == b'x'));
    }

    /// Server that sends 200 + a large Content-Length, writes `prefix` real
    /// body bytes, then goes silent (without closing) for `hang` — modelling a
    /// transfer that streams a while and then stalls mid-body. Returns the port.
    fn serve_then_stall(prefix: usize, hang: std::time::Duration) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut scratch = [0u8; 2048];
                let _ = sock.read(&mut scratch);
                // Claim far more than we send, so the client keeps waiting.
                let header =
                    "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(header.as_bytes());
                let _ = sock.write_all(&vec![b'x'; prefix]);
                let _ = sock.flush();
                // Go quiet. The client's idle window should fire well before this.
                std::thread::sleep(hang);
            }
        });
        port
    }

    #[test]
    fn streaming_times_out_on_an_idle_socket_not_on_total_time() {
        use std::time::{Duration, Instant};
        // 1 s idle window; server streams 128 KiB then hangs for 5 s mid-body.
        let prefix = 128 * 1024;
        let port = serve_then_stall(prefix, Duration::from_secs(5));
        let client = default_client(1);
        let mut stream = client
            .get_streaming(&format!("http://127.0.0.1:{port}/"), &[])
            .unwrap();
        assert_eq!(stream.status(), 200);
        let start = Instant::now();
        let mut buf = Vec::new();
        let err = stream.read_to_end(&mut buf).unwrap_err();
        // The idle window (≈1 s) trips, not the server's 5 s hang — proving the
        // bound is inactivity, not total elapsed time.
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "idle timeout should fire near the 1s window, took {:?}",
            start.elapsed()
        );
        // The bytes that streamed before the stall were delivered to the caller
        // (at least the first full pump chunk), not swallowed by the timeout.
        assert!(buf.len() >= 64 * 1024, "delivered {} bytes", buf.len());
        assert!(buf.iter().all(|&b| b == b'x'));
    }
}
