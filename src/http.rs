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

/// Minimum surface unpin needs from an HTTP client.
///
/// Contract:
/// - GET only.
/// - Follows redirects (302/301/307/308) up to a reasonable cap. GitHub's
///   `browser_download_url` always 302s to objects.githubusercontent.com.
/// - Returns the response as-is (no error mapping on non-2xx). Callers decide.
/// - `get` buffers the body; suitable for JSON API responses.
/// - `get_streaming` does not buffer; suitable for release-asset downloads.
pub trait HttpClient {
    fn get(&self, url: &str, headers: Headers) -> Result<HttpResponse, String>;
    fn get_streaming(
        &self,
        url: &str,
        headers: Headers,
    ) -> Result<Box<dyn HttpStream + Send>, String>;
}

#[cfg(feature = "http-minreq")]
pub fn default_client() -> Box<dyn HttpClient> {
    Box::new(minreq_backend::MinreqClient)
}

#[cfg(all(feature = "http-mbedtls", not(feature = "http-minreq")))]
pub fn default_client() -> Box<dyn HttpClient> {
    Box::new(mbedtls_backend::MbedtlsClient::new().expect("init mbedtls client"))
}

#[cfg(not(any(feature = "http-minreq", feature = "http-mbedtls")))]
compile_error!("at least one HTTP backend feature must be enabled (e.g. `http-minreq` or `http-mbedtls`)");

#[cfg(feature = "http-minreq")]
mod minreq_backend {
    use super::*;

    pub struct MinreqClient;

    impl HttpClient for MinreqClient {
        fn get(&self, url: &str, headers: Headers) -> Result<HttpResponse, String> {
            let mut req = minreq::get(url);
            for (k, v) in headers {
                req = req.with_header(*k, *v);
            }
            let resp = req.send().map_err(|e| format!("HTTP GET {url}: {e}"))?;
            let status = resp.status_code as u16;
            Ok(HttpResponse {
                status,
                body: resp.into_bytes(),
            })
        }

        fn get_streaming(
            &self,
            url: &str,
            headers: Headers,
        ) -> Result<Box<dyn HttpStream + Send>, String> {
            let mut req = minreq::get(url);
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

#[cfg(all(feature = "http-mbedtls", not(feature = "http-minreq")))]
mod mbedtls_backend {
    use super::*;
    use std::fmt::Write as _;
    use std::io::{BufRead, BufReader, Read as IoRead, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::time::Duration;

    use fluent_uri::{Uri, UriRef};
    use mbedtls::rng::{CtrDrbg, OsEntropy};
    use mbedtls::ssl::config::{AuthMode, Endpoint, Preset, Transport};
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::Certificate;

    const MAX_REDIRECTS: u8 = 10;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const IO_TIMEOUT: Duration = Duration::from_secs(60);
    const HEADER_MAX_BYTES: usize = 64 * 1024;
    const USER_AGENT_FALLBACK: &str = "unpin";

    static GITHUB_ROOTS_PEM: &[u8] = include_bytes!("../assets/github-roots.pem");

    pub struct MbedtlsClient {
        config: Arc<Config>,
    }

    impl MbedtlsClient {
        pub fn new() -> Result<Self, String> {
            let mut pem: Vec<u8> = Vec::with_capacity(GITHUB_ROOTS_PEM.len() + 1);
            pem.extend_from_slice(GITHUB_ROOTS_PEM);
            pem.push(0); // mbedtls expects null-terminated PEM
            let mut roots = Certificate::from_pem_multiple(&pem)
                .map_err(|e| format!("parse embedded CA roots: {e}"))?;

            // Append the platform trust store (Schannel on Windows, Security
            // Framework on macOS, ca-certificates file on Linux/BSD).
            let result = rustls_native_certs::load_native_certs();
            for der in result.certs {
                if let Ok(cert) = Certificate::from_der(&der) {
                    roots.push(cert);
                }
            }

            let entropy = Arc::new(OsEntropy::new());
            let rng =
                Arc::new(CtrDrbg::new(entropy, None).map_err(|e| format!("rng init: {e}"))?);

            let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
            config.set_authmode(AuthMode::Required);
            config.set_rng(rng);
            config.set_ca_list(Arc::new(roots), None);

            Ok(Self {
                config: Arc::new(config),
            })
        }

        fn open(&self, url: &str, headers: Headers) -> Result<MbedtlsStream, String> {
            let parsed = Uri::parse(url).map_err(|e| format!("parse URL {url}: {e}"))?;
            let scheme = parsed.scheme().as_str();
            if scheme != "https" {
                return Err(format!("only https is supported, got {scheme} for {url}"));
            }
            let auth = parsed
                .authority()
                .ok_or_else(|| format!("missing authority in {url}"))?;
            let host = auth.host().to_string();
            let port = auth
                .port_to_u16()
                .map_err(|e| format!("bad port in {url}: {e}"))?
                .unwrap_or(443);
            let path = parsed.path().as_str();
            let path = if path.is_empty() { "/" } else { path };
            let path_query = match parsed.query() {
                Some(q) => format!("{path}?{}", q.as_str()),
                None => path.to_string(),
            };

            let addrs: Vec<_> = (host.as_str(), port)
                .to_socket_addrs(host.as_str(), port)
                .map_err(|e| format!("resolve {host}:{port}: {e}"))?;
            let tcp = connect_with_timeout(&addrs, CONNECT_TIMEOUT)
                .map_err(|e| format!("connect {host}:{port}: {e}"))?;
            tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
            tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();

            let mut ctx = Context::new(self.config.clone());
            ctx.establish(tcp, Some(&host))
                .map_err(|e| format!("TLS handshake to {host}: {e}"))?;

            let mut req = String::with_capacity(256);
            let _ = write!(req, "GET {path_query} HTTP/1.1\r\n");
            let _ = write!(req, "Host: {host}\r\n");
            req.push_str("Connection: close\r\n");
            let mut have_ua = false;
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("connection") {
                    continue;
                }
                if k.eq_ignore_ascii_case("user-agent") {
                    have_ua = true;
                }
                let _ = write!(req, "{k}: {v}\r\n");
            }
            if !have_ua {
                let _ = write!(req, "User-Agent: {USER_AGENT_FALLBACK}\r\n");
            }
            req.push_str("\r\n");

            ctx.write_all(req.as_bytes())
                .map_err(|e| format!("write request to {host}: {e}"))?;

            let mut reader = BufReader::new(ctx);
            let (status, header_lines) = read_status_and_headers(&mut reader)?;
            let content_length = header_lines
                .iter()
                .find_map(|(k, v)| k.eq_ignore_ascii_case("content-length").then_some(v))
                .and_then(|s| s.trim().parse::<u64>().ok());
            let chunked = header_lines
                .iter()
                .find_map(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding").then_some(v))
                .map(|s| s.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false);
            let location = header_lines
                .iter()
                .find_map(|(k, v)| k.eq_ignore_ascii_case("location").then_some(v.clone()));

            let body_reader: Box<dyn IoRead + Send> = if chunked {
                Box::new(ChunkedReader::new(reader))
            } else if let Some(cl) = content_length {
                Box::new(reader.take(cl))
            } else {
                Box::new(reader)
            };

            Ok(MbedtlsStream {
                status,
                content_length,
                location,
                inner: body_reader,
            })
        }
    }

    impl HttpClient for MbedtlsClient {
        fn get(&self, url: &str, headers: Headers) -> Result<HttpResponse, String> {
            let mut current = url.to_string();
            for _ in 0..MAX_REDIRECTS {
                let mut stream = self.open(&current, headers)?;
                if is_redirect(stream.status)
                    && let Some(loc) = stream.location.clone()
                {
                    drop(stream);
                    current = resolve_url(&current, &loc)?;
                    continue;
                }
                let status = stream.status;
                let mut body = Vec::new();
                stream
                    .read_to_end(&mut body)
                    .map_err(|e| format!("read body: {e}"))?;
                return Ok(HttpResponse { status, body });
            }
            Err(format!("too many redirects (>{MAX_REDIRECTS}) for {url}"))
        }

        fn get_streaming(
            &self,
            url: &str,
            headers: Headers,
        ) -> Result<Box<dyn HttpStream + Send>, String> {
            let mut current = url.to_string();
            for _ in 0..MAX_REDIRECTS {
                let stream = self.open(&current, headers)?;
                if is_redirect(stream.status)
                    && let Some(loc) = stream.location.clone()
                {
                    drop(stream);
                    current = resolve_url(&current, &loc)?;
                    continue;
                }
                return Ok(Box::new(stream));
            }
            Err(format!("too many redirects (>{MAX_REDIRECTS}) for {url}"))
        }
    }

    struct MbedtlsStream {
        status: u16,
        content_length: Option<u64>,
        location: Option<String>,
        inner: Box<dyn IoRead + Send>,
    }

    impl IoRead for MbedtlsStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl HttpStream for MbedtlsStream {
        fn status(&self) -> u16 {
            self.status
        }
        fn content_length(&self) -> Option<u64> {
            self.content_length
        }
    }

    fn is_redirect(status: u16) -> bool {
        matches!(status, 301 | 302 | 303 | 307 | 308)
    }

    fn resolve_url(base: &str, location: &str) -> Result<String, String> {
        let base = Uri::parse(base).map_err(|e| format!("parse base {base}: {e}"))?;
        let loc = UriRef::parse(location)
            .map_err(|e| format!("parse location {location:?}: {e}"))?;
        let resolved = loc
            .resolve_against(&base)
            .map_err(|e| format!("resolve {location:?} against base: {e}"))?;
        Ok(resolved.to_string())
    }

    fn read_status_and_headers<R: BufRead>(
        reader: &mut R,
    ) -> Result<(u16, Vec<(String, String)>), String> {
        let mut all = Vec::with_capacity(1024);
        loop {
            let n = reader
                .read_until(b'\n', &mut all)
                .map_err(|e| format!("read headers: {e}"))?;
            if n == 0 {
                return Err("unexpected EOF in headers".into());
            }
            if all.ends_with(b"\r\n\r\n") || all.ends_with(b"\n\n") {
                break;
            }
            if all.len() > HEADER_MAX_BYTES {
                return Err("response headers too large".into());
            }
        }

        let s = std::str::from_utf8(&all).map_err(|_| "non-utf8 in response headers")?;
        let mut lines = s.split('\n');
        let status_line = lines.next().ok_or("missing status line")?.trim_end_matches('\r');
        let mut parts = status_line.splitn(3, ' ');
        let _version = parts.next().ok_or("malformed status line")?;
        let code = parts.next().ok_or("missing status code")?;
        let status: u16 = code.parse().map_err(|_| format!("bad status code {code:?}"))?;

        let mut headers = Vec::new();
        for line in lines {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        Ok((status, headers))
    }

    struct ChunkedReader<R: BufRead> {
        inner: R,
        remaining: u64,
        done: bool,
    }

    impl<R: BufRead> ChunkedReader<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                remaining: 0,
                done: false,
            }
        }
    }

    impl<R: BufRead> IoRead for ChunkedReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            use std::io::{Error, ErrorKind};
            if self.done {
                return Ok(0);
            }
            if self.remaining == 0 {
                let mut line = Vec::new();
                let n = self.inner.read_until(b'\n', &mut line)?;
                if n == 0 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "chunked: eof before size",
                    ));
                }
                let trimmed = std::str::from_utf8(&line)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "chunked: non-utf8 size"))?
                    .trim();
                let size_str = trimmed.split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(size_str, 16).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("chunked: bad size {size_str:?}"),
                    )
                })?;
                if size == 0 {
                    loop {
                        let mut tr = Vec::new();
                        let n = self.inner.read_until(b'\n', &mut tr)?;
                        if n == 0 {
                            break;
                        }
                        if tr == b"\r\n" || tr == b"\n" {
                            break;
                        }
                    }
                    self.done = true;
                    return Ok(0);
                }
                self.remaining = size;
            }
            let to_read = (self.remaining as usize).min(buf.len());
            let n = self.inner.read(&mut buf[..to_read])?;
            self.remaining -= n as u64;
            if self.remaining == 0 {
                let mut crlf = [0u8; 2];
                let _ = self.inner.read_exact(&mut crlf);
            }
            Ok(n)
        }
    }

    use std::net::{SocketAddr, ToSocketAddrs as StdToSocketAddrs};

    // Newtype trait so we can name the iterator on (&str, u16) explicitly.
    trait ToSocketAddrs {
        fn to_socket_addrs(self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
    }

    impl ToSocketAddrs for (&str, u16) {
        fn to_socket_addrs(self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            let iter = StdToSocketAddrs::to_socket_addrs(&self)?;
            Ok(iter.collect())
        }
    }

    fn connect_with_timeout(
        addrs: &[SocketAddr],
        timeout: Duration,
    ) -> std::io::Result<TcpStream> {
        let mut last_err: Option<std::io::Error> = None;
        for addr in addrs {
            match TcpStream::connect_timeout(addr, timeout) {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| std::io::Error::other("no addresses resolved")))
    }
}
