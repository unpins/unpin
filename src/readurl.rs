//! Optional generic HTTP-fetch hook for the static-musl DNS fallback shim.
//!
//! nix-lib's C `__wrap_getaddrinfo` shim resolves names over UDP/53 when there
//! is no `/etc/resolv.conf` (Android, minimal containers). When UDP/53 is *also*
//! blocked — captive portals, port-53 firewalls — it escalates to DoH over
//! HTTPS/443, but it carries no TLS of its own. Instead it calls this *weak*
//! hook: a dumb "fetch this URL" primitive we provide from the rustls stack
//! unpin already links (via minreq). The shim builds the whole DoH request and
//! parses the answer; this function knows nothing about DNS. A binary that
//! provides no hook simply stays UDP-only. See `unpin_readurl` in
//! nix-lib/dns-fallback/dns-fallback.c for the contract.
//!
//! The DoH resolver arrives as a v4 literal inside the URL, so the fetch needs
//! no prior name resolution — minreq's own `getaddrinfo("1.1.1.1")` goes back
//! through the shim, hits the numeric-literal fast path, and never recurses —
//! and rustls validates the cert against the IP-SAN that 1.1.1.1 / 8.8.8.8 both
//! carry (an all-digit host fails DNS-name validation, so rustls treats it as
//! an `IpAddress` and checks the certificate's iPAddress SAN, not a dNSName).

use std::ffi::{CStr, c_char, c_int};
use std::{ptr, slice};

/// Generic HTTP fetch invoked by the C DNS-fallback shim — see the module docs
/// and the `unpin_readurl` declaration in nix-lib/dns-fallback/dns-fallback.c.
///
/// Fetches `url` (POST `body` with `content_type` when non-empty, else GET) and
/// copies the response body into `result`, returning its length — or -1 on any
/// error, which tells the shim to try the next resolver / give up.
///
/// # Safety
/// Called only by the shim, which passes a NUL-terminated `url`, an optional
/// NUL-terminated `content_type`, and buffers valid for `bodylen` / `resultcap`
/// bytes. The crate is `panic = "abort"`, so this must not unwind: it stays
/// unwrap-free and turns every error into -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unpin_readurl(
    url: *const c_char,
    body: *const u8,
    bodylen: c_int,
    content_type: *const c_char,
    result: *mut u8,
    resultcap: c_int,
) -> c_int {
    if url.is_null() || result.is_null() || resultcap <= 0 {
        return -1;
    }
    // SAFETY: shim-provided NUL-terminated `url`, valid for the call. (Edition
    // 2024 requires the explicit blocks even inside an `unsafe fn`.)
    let url = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let body: &[u8] = if body.is_null() || bodylen <= 0 {
        &[]
    } else {
        // SAFETY: shim guarantees `body` readable for `bodylen` bytes.
        unsafe { slice::from_raw_parts(body, bodylen as usize) }
    };
    let content_type = if content_type.is_null() {
        None
    } else {
        // SAFETY: shim-provided NUL-terminated `content_type`.
        unsafe { CStr::from_ptr(content_type) }.to_str().ok()
    };
    match fetch(url, body, content_type) {
        Some(resp) if !resp.is_empty() && resp.len() <= resultcap as usize => {
            // SAFETY: `result` is writable for `resultcap` bytes; we copy ≤ that.
            unsafe { ptr::copy_nonoverlapping(resp.as_ptr(), result, resp.len()) };
            resp.len() as c_int
        }
        _ => -1,
    }
}

/// GET `url` (or POST `body` with `content_type`) and return the response body,
/// or `None` on any HTTP/TLS error or non-200 status.
fn fetch(url: &str, body: &[u8], content_type: Option<&str>) -> Option<Vec<u8>> {
    let mut req = if body.is_empty() {
        minreq::get(url)
    } else {
        minreq::post(url).with_body(body.to_vec())
    };
    if let Some(ct) = content_type {
        req = req
            .with_header("Content-Type", ct)
            .with_header("Accept", ct);
    }
    let resp = req.with_timeout(5).send().ok()?;
    if resp.status_code != 200 {
        return None;
    }
    Some(resp.as_bytes().to_vec())
}
