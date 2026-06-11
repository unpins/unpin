#!/usr/bin/env python3
"""Single source for the unpin terminal demo — both the recorded session and the
orchestration around it. Rendering the cast to SVGs stays in the Makefile (its
dependency tracking re-renders only when demo.cast or a template changes).

Subcommands:
  drive    Runs INSIDE termtosvg's PTY (termtosvg calls `-c "python3 demo.py
           drive"`). Types each prompt/comment one key at a time and runs the
           real unpin commands; the sleeps here become the animation timing.
  record   Orchestrates: seed a throwaway HOME, pre-cache the scene-1 package so
           it shows instantly, record the cast (termtosvg), validate it, and only
           then replace demo.cast. Then `make` turns the cast into the SVGs.

The scene script below (SCENES + the knobs above it) is the ONE place to edit
what the demo does; both `drive` and `record` read it, so changing a command or
the banner text touches a single spot.
"""
from __future__ import annotations
import json, os, random, shutil, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNPIN = os.environ.get("UNPIN", str(HERE.parent / "target/release/unpin"))
DL_KBPS = int(os.environ.get("DL_KBPS", "850"))   # trickle download cap (KB/s), install scene

# --- Scene script (single source of truth) ----------------------------------
# Each scene has: a gray "# note" line, the command text as TYPED on screen, the
# argv actually executed (without the leading "unpin"), and whether to throttle
# its download through trickle. `typed` and `run` differ on purpose — the typed
# line stays clean (quoted gradient, no `-j 2`) while `run` is the real argv.
SCENES = [
    dict(note="run a program straight from a GitHub release, no install",
         typed="unpin cfonts cool! -g '#3fb950,#0969da' -t",
         run=["cfonts", "cool!", "-g", "#3fb950,#0969da", "-t"]),
    dict(note="install several at once: catalog names + a GitHub repo",
         typed="unpin install htop jq BurntSushi/ripgrep tree nano",
         run=["install", "-j", "2", "htop", "jq", "BurntSushi/ripgrep", "tree", "nano"],
         throttle=True),
    dict(note="list what's installed",
         typed="unpin list",
         run=["list"]),
]

# --- Typing (drive) ----------------------------------------------------------
CHEVRON = "\033[34m❯\033[0m "   # ANSI-blue ❯ — adapts to theme at export
COMMENT = "\033[90m"                 # bright-black → template color8 (gray, both themes)
RESET = "\033[0m"
RNG = random.Random(7)               # seed: timing varies but reproduces


def cs(centi: int) -> None:
    time.sleep(centi / 100)


def w(s: str) -> None:
    sys.stdout.write(s)
    sys.stdout.flush()               # stdout is the PTY; flush so each key shows on its own


def type_at_prompt(text: str, color: str = "") -> None:
    """Type a string at a fresh prompt, one key at a time — fast but still human
    (jittered, longer at spaces/punctuation). The ❯ prints first, then the keys
    appear at it; $color, if set, tints the typed text (the ❯ keeps its blue)."""
    w(CHEVRON)
    if color:
        w(color)
    cs(18 + RNG.randrange(12))        # 0.18-0.29 beat after the prompt
    for c in text:
        w(c)
        if c == " ":
            cs(6 + RNG.randrange(6))  # 0.06-0.11 between words
        elif c in "./,-":
            cs(4 + RNG.randrange(5))  # 0.04-0.08 around punctuation
        else:
            cs(3 + RNG.randrange(4))  # 0.03-0.06 ordinary keys — visible per char
    if color:
        w(RESET)
    cs(12 + RNG.randrange(12))        # 0.12-0.23 beat before Enter
    w("\n")


def drive() -> int:
    cs(45)
    for sc in SCENES:
        type_at_prompt("# " + sc["note"], COMMENT)    # narration
        type_at_prompt(sc["typed"])                   # the command
        argv = [UNPIN, *sc["run"]]
        if sc.get("throttle"):
            # trickle caps the download bandwidth (LD_PRELOAD; works because the
            # dev unpin is dynamic) so the parallel progress bars stay watchable.
            argv = ["trickle", "-s", "-d", str(DL_KBPS), *argv]
        subprocess.run(argv)                          # inherits the PTY → recorded
    w(CHEVRON)                                         # leave a fresh prompt on screen
    cs(99); cs(99); cs(99); cs(50)                     # ~3.5s linger before the loop restarts
    return 0


# --- Orchestration (record) --------------------------------------------------
def die(msg: str) -> "NoReturn":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def resolve_termtosvg() -> str:
    t = os.environ.get("TERMTOSVG")
    if t:
        return t
    out = subprocess.run(["nix", "build", "nixpkgs#termtosvg", "--no-link", "--print-out-paths"],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        die("could not resolve termtosvg (set TERMTOSVG=…)")
    return out.stdout.strip().splitlines()[0] + "/bin/termtosvg"


def validate(cast: Path) -> tuple[bool, str]:
    """A good recording runs the three scenes to completion: it lasts well past
    the ~10s of a typing-only failure, confirms the install, and carries no shell
    errors. Reject anything else so demo.cast is only ever replaced by a real run."""
    try:
        lines = cast.read_text(encoding="utf-8").splitlines()
        events = [json.loads(l) for l in lines[1:] if l.startswith("[")]
    except Exception as e:
        return False, f"unreadable cast ({e})"
    if not events:
        return False, "no events recorded"
    text = "".join(e[2] for e in events if len(e) > 2 and e[1] == "o")
    dur = events[-1][0]
    for bad in ("No such file", "command not found", "inexistente", "não encontrado", "panic"):
        if bad in text:
            return False, f"cast contains shell/binary errors ({bad!r})"
    if "installed" not in text.lower():
        return False, "no install confirmation in cast"
    if dur < 14:
        return False, f"cast too short ({dur:.1f}s; expected ~18-22s)"
    return True, f"ok ({dur:.1f}s)"


def record() -> int:
    termtosvg = resolve_termtosvg()
    if not os.access(UNPIN, os.X_OK):
        die(f"unpin binary not found/executable at {UNPIN}\n"
            f"       build it first:  (cd {HERE.parent} && make release)")
    if not shutil.which("trickle"):
        die("trickle not on PATH")

    token = os.environ.get("GH_TOKEN") or subprocess.run(
        ["gh", "auth", "token"], capture_output=True, text=True).stdout.strip()

    # Throwaway HOME with the scene-1 package cached and the install targets absent.
    home = HERE / "sbox"
    shutil.rmtree(home, ignore_errors=True)
    (home / ".config/unpin").mkdir(parents=True)
    (home / ".config/unpin/config").write_text("http_timeout = 60\ndata = false\n")
    env = {**os.environ, "HOME": str(home), "UNPIN": UNPIN, "DL_KBPS": str(DL_KBPS),
           "GH_TOKEN": token, "GITHUB_TOKEN": token, "TERMTOSVG": termtosvg}

    print("caching scene-1 package...")
    for _ in range(5):
        if subprocess.run([UNPIN, *SCENES[0]["run"]], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            break

    tmp = HERE / ".demo.cast.new"
    print("recording...")
    # termtosvg ends recording when its own stdin hits EOF, so hand it a pipe we
    # never write to (the drive subcommand controls termination by exiting). It
    # makes its own sized pty via -g, so no external pty wrapper is needed.
    proc = subprocess.Popen(
        [termtosvg, "record", str(tmp), "-c", f"python3 {__file__} drive", "-g", "80x16"],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.wait()

    ok, msg = validate(tmp)
    if not ok:
        tmp.unlink(missing_ok=True)
        die(f"recording failed validation: {msg} — keeping the previous demo.cast")
    tmp.replace(HERE / "demo.cast")
    print(f"wrote demo.cast ({msg}) — now run 'make' to render the SVGs")
    return 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "drive":
        return drive()
    if cmd == "record":
        return record()
    print(__doc__)
    print("usage: demo.py {drive|record}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
