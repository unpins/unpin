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

pub fn default_client() -> Box<dyn HttpClient> {
    Box::new(minreq_backend::MinreqClient)
}

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

