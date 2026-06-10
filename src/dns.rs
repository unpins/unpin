//! Opt-in DNS fallback: the C-shim hook and the teach-on-failure UX.
//!
//! The static-musl / mingw / darwin binaries link a small C shim
//! (nix-lib/dns-fallback) that interposes `getaddrinfo`. By default it just
//! delegates to the OS resolver; it resolves through a public DNS server *only*
//! when the user opted in via `$UNPIN_DNS` or the config `dns` key — the shim
//! reads that config file itself, so the setting applies to every unpins
//! program, not only unpin. When a lookup needs the fallback but nothing is
//! configured, the shim calls the weak hook [`unpin_dns_note_unreachable`]
//! (which this module strong-overrides to set a flag) and surfaces the real
//! error. After a failed command, `main` checks [`was_resolver_unreachable`]
//! and, when set, calls [`offer_fallback`] to teach the user and — on a TTY —
//! offer to turn the fallback on now and save it.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::config;
use crate::install::prompt::{PromptResult, plain_yes_no};
use crate::platform::Paths;

/// The resolvers unpin suggests when the user opts in interactively: Cloudflare
/// then Google — the well-known anycast pair, both carrying the IP-SAN certs the
/// DoH leg validates against. Only ever a *suggestion* the user accepts; never a
/// silently-applied default (that opt-in choice is the whole point of the
/// redesign). `pub` for main's relaunch-with-`UNPIN_DNS` retry.
pub const SUGGESTED: &str = "1.1.1.1 8.8.8.8";

/// Set by [`unpin_dns_note_unreachable`] when the C shim reports a lookup that
/// needed the fallback but found no opt-in resolver configured.
static UNREACHABLE: AtomicBool = AtomicBool::new(false);

/// Strong override of the C shim's weak `unpin_dns_note_unreachable` (see
/// nix-lib/dns-fallback/dns-fallback.c). The shim calls this once when a lookup
/// can't reach the OS resolver and no opt-in resolver is configured. Linked and
/// called only from the C archive — kept by `#[no_mangle]`; on a plain host
/// build with no archive it is simply an unused export (never called), so the
/// binary still links cleanly.
///
/// May be called from any resolver thread, so the store is atomic.
#[unsafe(no_mangle)]
pub extern "C" fn unpin_dns_note_unreachable() {
    UNREACHABLE.store(true, Ordering::Relaxed);
}

/// Whether this run hit a "resolver unreachable, none configured" condition —
/// i.e. the DNS fallback could have helped had the user opted in. Always false
/// on a build without the shim linked (the hook is never called).
pub fn was_resolver_unreachable() -> bool {
    UNREACHABLE.load(Ordering::Relaxed)
}

/// After a command failed on a host whose resolver couldn't be reached, teach
/// the user about the opt-in DNS fallback. On an interactive terminal, offer to
/// turn it on for this run — and optionally save it to the config so every
/// unpins program uses it. Returns `true` when the user opted in and the caller
/// should relaunch the command once with `UNPIN_DNS=`[`SUGGESTED`] in the *new*
/// process' environment (see main's `relaunch_with_dns`).
///
/// Deliberately NO `env::set_var` here: the failed command can leave detached
/// HTTP pump threads behind (see `http::PumpStream` — a worker that hits its
/// idle window abandons its pump mid-request), and on this exact failure path
/// a stray pump may still be inside `getaddrinfo`, where the C shim calls
/// `getenv("UNPIN_DNS")`. Mutating our own environment under a possible
/// concurrent `getenv` is UB; building the child's environment via
/// `Command::env` never touches ours.
pub fn offer_fallback(paths: &Paths) -> bool {
    // We were latched as "no usable resolver". Usually that means none is
    // configured — but it also fires when a `dns` *is* set to something that
    // isn't valid IPv4 literals (a hostname, a typo): the shim accepts only v4
    // literals, so it found nothing to use. Don't silently overwrite the user's
    // value in that case; point them at the fix instead.
    if let Some(bad) = config::Config::load(&paths.config).dns() {
        eprintln!();
        eprintln!("unpin: can't reach a DNS server, and the config `dns = {bad}` isn't usable —");
        eprintln!("it must be space-separated IPv4 literals, e.g. `dns = {SUGGESTED}`.");
        eprintln!("Fix it in {} (or set UNPIN_DNS).", paths.config.display());
        return false;
    }

    eprintln!();
    eprintln!("unpin: can't reach a DNS server — the download host couldn't be resolved.");
    eprintln!("This host has no working resolver (common on Android, minimal containers, or");
    eprintln!("behind a blocked nameserver). unpin can resolve through a public DNS server,");
    eprintln!("but only if you turn it on:");
    eprintln!();
    eprintln!("  one run:   UNPIN_DNS=\"{SUGGESTED}\" unpin …");
    eprintln!(
        "  always:    add `dns = {SUGGESTED}` to {}",
        paths.config.display()
    );
    eprintln!("             (then every unpins program uses it)");

    // Non-interactive (piped/CI): we can't ask. The teaching above stands; the
    // caller surfaces the original error and exits non-zero.
    // Name both servers: saying yes opts into sending lookups to Cloudflare
    // AND Google, and that consent should be informed.
    match plain_yes_no(&format!("\nTry resolving through {SUGGESTED} now?")) {
        PromptResult::Got(true) => {}
        PromptResult::Got(false) | PromptResult::Skip => return false,
    }

    // Offer to persist it. A bare "no" or non-TTY just skips saving; the
    // relaunch (with `UNPIN_DNS` in the child's environment) still covers this
    // run either way.
    if let PromptResult::Got(true) =
        plain_yes_no("Save this to your config so every unpins program uses it?")
    {
        match config::write_dns(&paths.config, SUGGESTED) {
            Ok(()) => eprintln!(
                "unpin: saved `dns = {SUGGESTED}` to {}",
                paths.config.display()
            ),
            Err(e) => eprintln!("unpin: couldn't write config ({e}); using it for this run only"),
        }
    }
    true
}
