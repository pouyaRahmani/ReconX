#!/usr/bin/env bash
# ReconX bootstrap — creates a virtual environment, installs Python
# dependencies, prepares the shell environment for the external recon tools
# (Go bin directory, oh-my-zsh `gau` alias) and reports tool status.
#
# Usage:
#   bash setup.sh                  # Python env + shell/PATH fixes
#   bash setup.sh --install-tools  # also `go install` the recon tools + uro
#   ./setup.sh                     # same, once the executable bit is set
#
# Git can store setup.sh/reconx as 100644 (the repo was committed from
# Windows), which is why `./setup.sh` may answer "permission denied" after a
# fresh clone. `bash setup.sh` always works, and the script re-applies the
# executable bits for later runs.
set -euo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

VENV_DIR="${RECONX_VENV:-$DIR/.venv}"
INSTALL_TOOLS="${RECONX_INSTALL_TOOLS:-0}"

for arg in "$@"; do
    case "$arg" in
        --install-tools) INSTALL_TOOLS=1 ;;
        --no-install-tools) INSTALL_TOOLS=0 ;;
        -h|--help)
            cat <<'EOF'
ReconX bootstrap.

Usage:
  bash setup.sh                  # Python env + shell/PATH fixes
  bash setup.sh --install-tools  # also `go install` the recon tools + uro
  ./setup.sh                     # same, once the executable bit is set
EOF
            exit 0
            ;;
        *)
            echo "[ - ] unknown option: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

# --- keep the launchers executable ----------------------------------------
chmod +x "$DIR/setup.sh" "$DIR/reconx" 2>/dev/null || true

# --- external tool PATH ----------------------------------------------------
# `gau`, `katana`, `nuclei`, … live in $(go env GOPATH)/bin; `uro` lives in a
# pipx shim under ~/.local/bin.  Both are prepended so the real binaries win
# over anything else on PATH (including shell aliases, see below).
GO_BIN="${GOBIN:-}"
if [[ -z "$GO_BIN" ]] && command -v go >/dev/null 2>&1; then
    go_path="$(go env GOPATH 2>/dev/null || true)"
    if [[ -n "$go_path" ]]; then
        GO_BIN="$go_path/bin"
    fi
fi
GO_BIN="${GO_BIN:-$HOME/go/bin}"
LOCAL_BIN="$HOME/.local/bin"

path_add() {
    case ":$PATH:" in
        *":$1:"*) ;;
        *) PATH="$1:$PATH" ;;
    esac
}

path_add "$GO_BIN"
path_add "$LOCAL_BIN"
export PATH

# --- shell startup files ---------------------------------------------------
RC_MARKER="# >>> reconx environment >>>"
read -r -d '' RC_BLOCK <<'EOF' || true
# >>> reconx environment >>>
# Go-installed recon tools (gau, waybackurls, katana, nuclei, …) and the
# pipx shim directory. Prepended so the real binaries take precedence.
for _reconx_dir in "$HOME/go/bin" "$HOME/.local/bin"; do
    case ":$PATH:" in
        *":$_reconx_dir:"*) ;;
        *) PATH="$_reconx_dir:$PATH" ;;
    esac
done
export PATH
unset _reconx_dir
# oh-my-zsh's git plugin ships `alias gau='git add --update'`, which shadows
# the gau URL collector. Drop the alias so `gau` means gau everywhere.
unalias gau 2>/dev/null || true
# <<< reconx environment <<<
EOF

echo "[ * ] Configuring shell environment"
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [[ -f "$rc" ]] || continue
    if grep -qF "$RC_MARKER" "$rc" 2>/dev/null; then
        echo "[ = ] $rc already configured"
        continue
    fi
    {
        printf '\n'
        printf '%s\n' "$RC_BLOCK"
    } >> "$rc"
    echo "[ + ] added tool PATH + gau alias fix to $rc"
done

# Report the alias problem for the shell the user is already in: appending to
# .zshrc cannot change the alias table of a running shell.
if command -v zsh >/dev/null 2>&1; then
    gau_alias="$(zsh -ic 'alias gau' 2>/dev/null || true)"
    if [[ "$gau_alias" == *"git add"* ]]; then
        echo "[ ! ] this zsh session still aliases gau to git: $gau_alias"
        echo "      open a new shell, or run: unalias gau"
    fi
fi

# --- pick an interpreter ---------------------------------------------------
PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PYTHON="$candidate"
            break
        fi
    done
fi
if [[ -z "$PYTHON" ]]; then
    echo "[ - ] python3 not found. On Kali/Debian run:" >&2
    echo "        sudo apt update && sudo apt install -y python3 python3-venv python3-pip" >&2
    exit 1
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    echo "[ - ] $("$PYTHON" -V 2>&1) is too old; ReconX needs Python 3.9+." >&2
    exit 1
fi

# A usable venv needs a working interpreter *and* the activation scripts;
# a half-written venv (interrupted `python -m venv`) has neither.
venv_ok() {
    [[ -x "$VENV_DIR/bin/python" ]] \
        && [[ -f "$VENV_DIR/bin/activate" ]] \
        && "$VENV_DIR/bin/python" -c 'import sys' >/dev/null 2>&1
}

if ! venv_ok; then
    if [[ -e "$VENV_DIR" ]]; then
        echo "[ ! ] $VENV_DIR is incomplete or broken — recreating it"
        rm -rf "$VENV_DIR"
    fi
    echo "[ * ] Creating virtual environment in $VENV_DIR"
    if ! "$PYTHON" -m venv "$VENV_DIR" || ! venv_ok; then
        echo "[ - ] Failed to create a usable virtual environment." >&2
        echo "      On Kali/Debian install the venv module first:" >&2
        echo "        sudo apt update && sudo apt install -y python3-venv python3-pip" >&2
        echo "      Then re-run ./setup.sh" >&2
        exit 1
    fi
fi

# Call the venv interpreter directly instead of `source activate`; this works
# in non-interactive shells and survives broken activation scripts.
VENV_PY="$VENV_DIR/bin/python"

echo "[ * ] Installing Python dependencies"
"$VENV_PY" -m pip install --disable-pip-version-check --upgrade pip >/dev/null 2>&1 \
    || echo "[ ! ] could not upgrade pip; continuing with the bundled version"
"$VENV_PY" -m pip install --disable-pip-version-check -r requirements.txt

echo "[ * ] Verifying Python dependencies"
if ! "$VENV_PY" -c 'import click, requests, yaml' >/dev/null 2>&1; then
    echo "[ - ] dependency check failed. Re-run:" >&2
    echo "        $VENV_PY -m pip install -r requirements.txt" >&2
    exit 1
fi

# --- optional: install the Go recon tools ----------------------------------
if [[ "$INSTALL_TOOLS" == "1" ]]; then
    if ! command -v go >/dev/null 2>&1; then
        echo "[ - ] Go is not installed, so the recon tools cannot be installed." >&2
        echo "      Ubuntu/Debian: sudo apt install -y golang-go" >&2
        echo "      Other systems: https://go.dev/dl/" >&2
        exit 1
    fi
    tool_failures=0
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] || continue
        echo "[ * ] go install $pkg"
        go install "$pkg" || { echo "[ ! ] failed to install $pkg" >&2; tool_failures=1; }
    done <<'EOF'
github.com/tomnomnom/waybackurls@latest
github.com/lc/gau/v2/cmd/gau@latest
github.com/projectdiscovery/katana/cmd/katana@latest
github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
EOF
    if ! command -v uro >/dev/null 2>&1; then
        if command -v pipx >/dev/null 2>&1; then
            echo "[ * ] pipx install uro"
            pipx install uro || { echo "[ ! ] failed to install uro" >&2; tool_failures=1; }
        else
            echo "[ ! ] uro is optional and not installed; use: pipx install uro" >&2
        fi
    fi
    if [[ "$tool_failures" -ne 0 ]]; then
        echo "[ ! ] some tools failed to install; re-run: bash setup.sh --install-tools" >&2
    fi
fi

echo
echo "[ + ] ReconX is ready. Run: ./reconx doctor"
echo "     Missing Go tools can be installed with: bash setup.sh --install-tools"
echo
echo "[ * ] Tool status"
./reconx doctor || true
