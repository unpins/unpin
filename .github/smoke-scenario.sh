#!/usr/bin/env bash
# A real unpin session against the live GitHub API: install a catalog
# package, execute it, read its embedded manual through the `man` helper
# verb, inspect the bundle, update, uninstall. Run by the Extended smoke
# workflow on all three OSes — on the windows runner this executes under
# git-bash. GITHUB_TOKEN should be set: the runners' shared IPs exhaust the
# anonymous 60/h API limit quickly.
#
# Command output is captured into variables, not piped into grep/head — an
# early-exiting pipe reader would kill unpin with SIGPIPE, which reads as a
# failure under pipefail.
set -euo pipefail

UNPIN="$1"

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    BIN_DIR="${LOCALAPPDATA}\\unpin"
    EXE=".exe"
    ;;
  *)
    BIN_DIR="${HOME}/.local/bin"
    EXE=""
    ;;
esac

run() {
  echo "+ $*" >&2
  "$@"
}

run "$UNPIN" --version

run "$UNPIN" install -y jq
run "${BIN_DIR}/jq${EXE}" --version

LIST_OUT="$(run "$UNPIN" list)"
echo "$LIST_OUT"
grep -q jq <<<"$LIST_OUT"

# The helper verb: fetches the unpins/unpin-man package and renders jq's
# embedded manual. Exercises run-dispatch + the embedded-metadata reader on
# this OS in one go.
MAN_OUT="$(run "$UNPIN" man jq)"
grep -qi "jq" <<<"$MAN_OUT"
echo "man jq: rendered $(wc -l <<<"$MAN_OUT") lines"

BUNDLE_OUT="$(run "$UNPIN" bundle list jq)"
echo "$BUNDLE_OUT"
grep -q "unpin/man/jq" <<<"$BUNDLE_OUT"

run "$UNPIN" update -y

run "$UNPIN" uninstall -y

echo "extended smoke: OK"
