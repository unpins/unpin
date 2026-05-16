//! Types that drive the unified install/update pipeline (`run_pipeline_v2`).
//!
//! `PipelineRequest` is the per-package input; `PipelineMode` switches between
//! the install-time and update-time behavior of the dispatcher.
//!
//! `PrepareOutcome` is what each parallel preflight worker emits. The
//! dispatcher consumes these to decide whether a job is ready to extract,
//! needs an interactive prompt first, is already up to date, or already
//! cached on disk. Workers do the network-bound part; the dispatcher does
//! the prompts and the lock acquisition.

use super::spec::Spec;
use crate::github::{Asset, Release};

/// Switches dispatcher behavior between the two entry points.
///
/// `Install` is the default — every request must produce an install attempt;
/// "already installed at this version" is still a no-op extract followed by
/// linking. `Update` adds an early short-circuit: if the package's currently
/// linked version equals the latest release tag, the request finishes silently
/// as "up to date" without touching the lock or extract path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipelineMode {
    Install,
    Update,
}

/// One pipeline input. `label` is the user-facing identifier — original argv
/// string for install, `owner/repo` for update — used as the bar prefix and
/// in error messages. `spec` carries the resolved parsing result with the
/// optional `@version` tag preserved.
pub struct PipelineRequest {
    pub label: String,
    pub spec: Spec,
}

/// Result emitted by one parallel preflight worker. The dispatcher pattern-
/// matches on this to decide whether to finalize the bar (UpToDate), build
/// an `ExtractJob` (Ready / Cached), or pause for an interactive prompt
/// before continuing (NeedsPrompt).
///
/// The variants are boxed where the payload is large enough that the enum
/// would otherwise be unbalanced (each `Release` carries a `Vec<Asset>`).
pub enum PrepareOutcome {
    /// `PipelineMode::Update` + `active_version()` already matches the
    /// latest release tag. Bar finishes as "Up to date (vX)" and no
    /// further work happens for this request.
    UpToDate(Box<Release>),
    /// The version dir is already on disk and complete (companion present
    /// when needed). Skip the download entirely; the linker still runs so
    /// any new aliases or removed companion symlinks get applied.
    Cached(Box<Release>),
    /// Resolution complete — no prompt needed. The dispatcher acquires the
    /// per-repo lock, wipes any stale `.part` dir, and hands the resulting
    /// `ExtractJob` to the extract pool.
    Ready(Box<ResolutionData>),
    /// A user prompt blocks completion. `data` carries everything resolved
    /// so far; after the dispatcher prompts the user it fills in the rest
    /// (checksum fetch for the chosen asset, missing-checksum confirmation)
    /// before acquiring the lock.
    NeedsPrompt(PromptKind, Box<ResolutionData>),
}

/// Reason a `PrepareOutcome::NeedsPrompt` is awaiting user input.
pub enum PromptKind {
    /// Narrowing left more than one candidate, or `--pick` forced a prompt.
    AssetPicker,
    /// Release has no `.sha256`/`.sha256sum` sidecar for the chosen asset.
    MissingChecksum,
    /// Same for the data companion. Distinct so the message text matches
    /// what the user actually sees on disk ("(data)" tag).
    MissingCompanionChecksum,
}

/// All the data a preflight worker can resolve without prompting. Most fields
/// are populated on the network-bound parallel pass; the rest get filled in
/// by the dispatcher after any prompt resolves.
pub struct ResolutionData {
    pub release: Release,
    /// The single chosen asset. `Some` whenever narrow_assets returned a
    /// unique candidate; `None` only on the `AssetPicker` path, until the
    /// dispatcher resolves the prompt.
    pub asset: Option<Asset>,
    /// Full candidate list for the `AssetPicker` prompt. Empty otherwise.
    pub candidates: Vec<Asset>,
    pub expected_sha256: Option<String>,
    pub companion: Option<Asset>,
    pub companion_expected_sha256: Option<String>,
    /// `true` when the release has no `.sha256` sidecar for the chosen
    /// primary asset. With `--yes` the dispatcher prints a warning and
    /// proceeds; without it, the dispatcher converts this into a
    /// `MissingChecksum` prompt.
    pub primary_checksum_missing: bool,
    pub companion_checksum_missing: bool,
}
