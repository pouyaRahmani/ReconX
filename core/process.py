"""Subprocess helpers.

Every external tool is executed with an argument list (never through a shell),
which prevents command injection from target data.  Piped tools receive their
input through ``stdin``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass

from core import ui


@dataclass
class ProcResult:
    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    #: True when the process was killed because it stopped producing output.
    stalled: bool = False

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


def _kill(process: subprocess.Popen) -> None:
    try:
        process.kill()
    except OSError:
        pass


def _join(thread: threading.Thread, timeout: float) -> None:
    try:
        thread.join(timeout=timeout)
    except RuntimeError:  # pragma: no cover - thread never started
        pass


def run_to_file(
    cmd: list[str],
    output_path: str | os.PathLike[str],
    *,
    input_text: str | None = None,
    timeout: float | None = None,
    stall_timeout: float | None = None,
    max_output_bytes: int | None = None,
    poll_interval: float = 1.0,
    env: dict[str, str] | None = None,
    quiet: bool = False,
) -> ProcResult:
    """Run *cmd* and stream stdout to *output_path*.

    Unlike :func:`run`, the output is never held in memory, so tools that emit
    very large output (katana JSONL on a big site) cannot exhaust RAM.

    ``stall_timeout`` kills the process when *output_path* has not grown for
    that many seconds, and ``max_output_bytes`` stops it once the capture gets
    that large.  Both guard against crawlers that hang on a single streaming
    response or fall into a crawler trap and never finish on their own.
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
            stderr_chunks: list[str] = []

            def _drain_stderr() -> None:
                try:
                    stderr_chunks.append(process.stderr.read() or "")
                except (OSError, ValueError):
                    pass

            def _feed_stdin() -> None:
                try:
                    if input_text:
                        process.stdin.write(input_text)
                    process.stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    pass

            # Feeding stdin and draining stderr must not block the watchdog.
            drain = threading.Thread(target=_drain_stderr, daemon=True)
            drain.start()
            feeder = threading.Thread(target=_feed_stdin, daemon=True)
            feeder.start()

            started = time.monotonic()
            last_size = 0
            last_growth = started
            timed_out = False
            stalled = False
            try:
                while True:
                    try:
                        process.wait(timeout=max(0.05, poll_interval))
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    now = time.monotonic()
                    try:
                        size = os.path.getsize(output_path)
                    except OSError:
                        size = last_size
                    if size > last_size:
                        last_size = size
                        last_growth = now
                    if timeout is not None and now - started >= timeout:
                        timed_out = True
                        break
                    if stall_timeout and now - last_growth >= stall_timeout:
                        stalled = True
                        break
                    if max_output_bytes and size >= max_output_bytes:
                        stalled = True
                        break
                if timed_out or stalled:
                    _kill(process)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
            except BaseException:
                _kill(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise
            finally:
                _join(feeder, 1)
                _join(drain, 5)
    except OSError as exc:
        return ProcResult(args=cmd, returncode=1, stderr=str(exc))

    stderr = "".join(stderr_chunks).strip()
    if stalled:
        detail = stderr
        if max_output_bytes and last_size >= max_output_bytes:
            reason = f"capture limit reached ({last_size} bytes)"
        else:
            reason = f"no new output for {stall_timeout:g}s"
        return ProcResult(
            args=cmd,
            returncode=124,
            stderr=detail or f"stopped: {reason}",
            timed_out=True,
            stalled=True,
        )
    if timed_out:
        return ProcResult(
            args=cmd,
            returncode=124,
            stderr=stderr or f"timed out after {timeout}s",
            timed_out=True,
        )
    return ProcResult(
        args=cmd,
        returncode=process.returncode,
        stderr=stderr,
    )
