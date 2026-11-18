#!/usr/bin/env bash
# ReconX bootstrap — creates a virtual environment, installs Python
# dependencies and reports external tool status.
set -euo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

VENV_DIR="${RECONX_VENV:-$DIR/.venv}"

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

chmod +x reconx

echo
echo "[ + ] ReconX is ready. Run: ./reconx doctor"
echo "     Missing Go tools can be installed with the commands printed by doctor."
echo
echo "[ * ] Tool status"
./reconx doctor || true
