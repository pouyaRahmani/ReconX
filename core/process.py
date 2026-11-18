"""Subprocess helpers.

Every external tool is executed with an argument list (never through a shell),
which prevents command injection from target data.  Piped tools receive their
input through ``stdin``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from core import ui


@dataclass
class ProcResult:
    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def missing(self) -> bool:
        return self.returncode == 127


def which(tool: str) -> str | None:
    """Return the resolved path for *tool*, or ``None``."""
    if not tool:
        return None
    if os.path.isabs(tool) and os.path.isfile(tool):
        return tool
    return shutil.which(tool)


def run(
    cmd: list[str],
    *,
    input_text: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    quiet: bool = False,
) -> ProcResult:
    """Execute *cmd* and capture its output.

    Missing binaries and timeouts are returned as failed results instead of
    raising, so a recon run can continue with the remaining tools.
    """
    if not cmd:
        return ProcResult(args=cmd, returncode=2, stderr="empty command")

    if which(cmd[0]) is None:
        return ProcResult(
            args=cmd,
            returncode=127,
            stderr=f"tool not found on PATH: {cmd[0]}",
        )

    if not quiet:
        ui.debug("exec: " + " ".join(cmd[:8]) + (" ..." if len(cmd) > 8 else ""))

    merged_env = os.environ.copy()
    # Tools should not emit ANSI when their output is parsed.
    merged_env.setdefault("NO_COLOR", "1")
    if env:
        merged_env.update(env)

    try:
        completed = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            check=False,
        )
        return ProcResult(
            args=cmd,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return ProcResult(
            args=cmd,
            returncode=124,
            stdout=stdout,
            stderr=stderr or f"timed out after {timeout}s",
            timed_out=True,
        )
    except OSError as exc:
        return ProcResult(args=cmd, returncode=1, stderr=str(exc))


def run_tool(
    tool: str,
    args: list[str] | None = None,
    **kwargs,
) -> ProcResult:
    """Run *tool* with *args* (thin wrapper used by the recon modules)."""
    return run([tool, *(args or [])], **kwargs)


def run_to_file(
    cmd: list[str],
    output_path: str | os.PathLike[str],
    *,
    input_text: str | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    quiet: bool = False,
) -> ProcResult:
    """Run *cmd* and stream stdout to *output_path*.

    Unlike :func:`run`, the output is never held in memory, so tools that emit
    very large output (katana JSONL on a big site) cannot exhaust RAM.
    """
    if not cmd:
        return ProcResult(args=cmd, returncode=2, stderr="empty command")

    if which(cmd[0]) is None:
        return ProcResult(
            args=cmd,
            returncode=127,
            stderr=f"tool not found on PATH: {cmd[0]}",
        )

    if not quiet:
        ui.debug("exec: " + " ".join(cmd[:8]) + (" ..." if len(cmd) > 8 else ""))

    merged_env = os.environ.copy()
    merged_env.setdefault("NO_COLOR", "1")
    if env:
        merged_env.update(env)

    try:
        with open(output_path, "w", encoding="utf-8", errors="replace") as handle:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=handle,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=merged_env,
            )
            try:
                _, stderr = process.communicate(input=input_text, timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
                return ProcResult(
                    args=cmd,
                    returncode=124,
                    stderr=(stderr or "").strip()
                    or f"timed out after {timeout}s",
                    timed_out=True,
                )
            except BaseException:
                process.kill()
                try:
                    process.communicate(timeout=5)
                except Exception:
                    pass
                raise
        return ProcResult(
            args=cmd,
            returncode=process.returncode,
            stderr=stderr or "",
        )
    except OSError as exc:
        return ProcResult(args=cmd, returncode=1, stderr=str(exc))
