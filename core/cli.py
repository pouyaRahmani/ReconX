"""Command-line interface for ReconX."""

from __future__ import annotations

import json
import shutil

import click

from core import __version__, ui
from core.config_loader import (
    ConfigError,
    default_target_config,
    load_settings,
    load_target_config,
    validate_config,
    write_sample_config,
)
from core.deps import TOOLS, doctor as run_doctor
from core.models import VALID_CONTENT_TYPES, VALID_METHODS, TargetConfig
from core.paths import Workspace, project_root, results_dir_from_env, safe_component
from core.pipeline import (
    MassFuzzOptions,
    SingleFuzzOptions,
    run_mass_fuzz,
    run_single_fuzz,
)
from core.recon import active as active_mod
from core.recon import passive as passive_mod
from core.recon.active import ActiveOptions
from core.recon.passive import PassiveOptions
from core.recon.urls import parse_host
from core.report import aggregate as aggregate_results
from core.state import State, disk_status

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


class ReconXGroup(click.Group):
    """Click group that turns configuration/value errors into clean messages."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (ConfigError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _settings(ctx) -> dict:
    return ctx.obj["settings"]


def _workspace(ctx) -> Workspace:
    return ctx.obj["workspace"]


def _parse_header_option(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise click.BadParameter(f"expected 'Name: value', got {value!r}")
    name, _, header_value = value.partition(":")
    name, header_value = name.strip(), header_value.strip()
    if not name or not header_value:
        raise click.BadParameter(f"invalid header: {value!r}")
    return name, header_value


def _with_overrides(cfg: TargetConfig, settings: dict, **overrides) -> TargetConfig:
    clean = {key: value for key, value in overrides.items() if value is not None}
    if not clean:
        return cfg
    raw = cfg.to_dict()
    raw.update(clean)
    return validate_config(raw, settings)


def _print_passive_summary(result) -> None:
    ui.step("passive summary")
    ui.kv("hosts", len(result.per_host))
    ui.kv("total URLs", result.urls)
    for host, count in sorted(result.per_host.items(), key=lambda kv: -kv[1]):
        ui.kv(host, f"{count} URL(s)")
    if result.errors:
        ui.warn(f"{len(result.errors)} warning(s)")
        for message in result.errors[-5:]:
            print(f"    {message}")


def _require_target_dir(target_paths, target: str) -> None:
    if not target_paths.root.is_dir():
        raise click.ClickException(
            f"target '{target}' has no results yet. Run passive/active first."
        )


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group(cls=ReconXGroup, context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.option("--no-color", is_flag=True, help="Disable ANSI colours.")
@click.option("--debug", "-d", is_flag=True, help="Verbose debug output.")
@click.version_option(__version__, "-V", "--version", prog_name="reconx")
@click.pass_context
def cli(ctx, no_color: bool, debug: bool):
    """ReconX — modular web vulnerability reconnaissance framework."""
    ui.configure(color=False if no_color else None, verbose=debug)
    ui.banner(__version__)

    ctx.ensure_object(dict)
    ctx.obj["workspace"] = Workspace(results_dir_from_env())
    ctx.obj["settings"] = load_settings()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# passive
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("seed")
@click.option("-t", "--target", default=None, help="Target name (defaults to the seed host).")
@click.option("--subs", "subs_file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="File with additional subdomains (one per line).")
@click.option("--enumerate", is_flag=True, help="Enumerate subdomains with subfinder.")
@click.option("--no-wayback", is_flag=True, help="Skip waybackurls.")
@click.option("--no-gau", is_flag=True, help="Skip gau.")
@click.option("--no-uro", is_flag=True, help="Skip the uro URL filter.")
@click.option("--max-hosts", type=int, default=500, show_default=True, help="Maximum hosts to process.")
@click.option("-c", "--config", "config_path", type=click.Path(exists=True, dir_okay=False),
              default=None, help="Optional target config (scope/ignore rules).")
@click.pass_context
def passive(ctx, seed, target, subs_file, enumerate, no_wayback, no_gau, no_uro, max_hosts, config_path):
    """Gather archived URLs (waybackurls + gau + uro)."""
    settings = _settings(ctx)
    workspace = _workspace(ctx)

    host = parse_host(seed)
    if not host:
        raise click.ClickException(f"cannot parse host from {seed!r}")

    if config_path:
        cfg = load_target_config(config_path, settings)
        if target and target != cfg.target:
            raise click.ClickException(
                f"--target '{target}' does not match config target '{cfg.target}'"
            )
        target = cfg.target
    else:
        target = target or host
        cfg = default_target_config(target, seeds=[seed], settings=settings)

    hosts = [host]
    for seed_url in cfg.seeds:
        seed_host = parse_host(seed_url)
        if seed_host and seed_host not in hosts:
            hosts.append(seed_host)
    if cfg.sub and cfg.sub not in hosts:
        hosts.append(cfg.sub)

    options = PassiveOptions(
        wayback=not no_wayback,
        gau=not no_gau,
        use_uro=not no_uro,
        enumerate=enumerate,
        subdomains_file=subs_file or "",
        max_hosts=max(1, max_hosts),
    )
    ui.step(f"passive recon — {target}")
    ui.kv("seed", host)
    ui.kv("target", target)
    if enumerate:
        ui.kv("enumeration", "subfinder")

    try:
        result = passive_mod.run_passive(workspace, target, hosts, settings, cfg, options)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    _print_passive_summary(result)
    ui.ok(f"passive recon complete — results under {workspace.target(target).root}")


# ---------------------------------------------------------------------------
# active
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-t", "--target", required=True, help="Target name.")
@click.option("--sub", "subs", multiple=True, help="Limit to specific subdomain(s).")
@click.option("--depth", type=int, default=3, show_default=True, help="Crawl depth.")
@click.option("--refresh", is_flag=True, help="Re-crawl even if results exist.")
@click.option("--max-seeds", type=int, default=None,
              help="Cap katana seeds per host after prioritisation (0 = no cap).")
@click.option("--no-forms", is_flag=True, help="Disable automatic form filling (faster).")
@click.option("--no-js", is_flag=True, help="Disable JavaScript crawling (faster).")
@click.option("--duration", type=int, default=None,
              help="Abort the crawl after N seconds (partial results are kept).")
@click.option("--header", "header_options", multiple=True, help="Extra header 'Name: value'.")
@click.option("-c", "--config", "config_path", type=click.Path(exists=True, dir_okay=False),
              default=None, help="Optional target config.")
@click.pass_context
def active(ctx, target, subs, depth, refresh, max_seeds, no_forms, no_js,
           duration, header_options, config_path):
    """Actively crawl targets with Katana (JS + forms)."""
    settings = _settings(ctx)
    workspace = _workspace(ctx)
    target_paths = workspace.target(target)
    _require_target_dir(target_paths, target)

    cfg = (
        load_target_config(config_path, settings)
        if config_path
        else default_target_config(target, settings=settings)
    )

    hosts = target_paths.hosts()
    if subs:
        wanted = set(subs)
        hosts = [host for host in hosts if host in wanted]
        missing = wanted - set(hosts)
        if missing:
            ui.warn(f"unknown subdomain(s): {', '.join(sorted(missing))}")
    if not hosts:
        raise click.ClickException("no subdomain directories to crawl")

    extra_headers = dict(_parse_header_option(option) for option in header_options)
    options = ActiveOptions(
        depth=max(1, depth),
        refresh=refresh,
        extra_headers=extra_headers,
        max_seeds=max_seeds,
        automatic_form_fill=not no_forms,
        js_crawl=not no_js,
        timeout=float(duration) if duration else None,
    )

    ui.step(f"active crawl — {target}")
    stats = []
    for host in hosts:
        stats.append(active_mod.crawl_host(target_paths, host, settings, cfg, options))

    ui.step("active summary")
    for item in stats:
        ui.kv(item.host, f"{item.urls} URL(s), {item.requests} request(s), {item.forms} form(s)")
    errors = [error for item in stats for error in item.errors]
    if errors:
        ui.warn(f"{len(errors)} warning(s) during crawl")
    ui.ok("active crawl complete")


# ---------------------------------------------------------------------------
# mass-fuzz
# ---------------------------------------------------------------------------

@cli.command("mass-fuzz")
@click.option("-c", "--config", "config_path", required=True,
              type=click.Path(exists=True, dir_okay=False), help="Target config JSON.")
@click.option("--only", multiple=True, help="Only process these subdomains.")
@click.option("--resume", is_flag=True, help="Skip subdomains already marked done.")
@click.option("--keep-templates", is_flag=True, help="Keep templates/ after each host.")
@click.option("--skip-fuzz", is_flag=True, help="Generate templates but do not fuzz.")
@click.option("--skip-nuclei", is_flag=True, help="Do not run nuclei.")
@click.option("--refresh-params", is_flag=True, help="Re-extract parameters.")
@click.option("--refresh-fuzz", is_flag=True, help="Fuzz even when marked done.")
@click.option("--max-hosts", type=int, default=None, help="Process at most N subdomains.")
@click.option("--rl", type=int, default=None, help="Override requests/second.")
@click.option("--workers", type=int, default=None, help="Override concurrency.")
@click.option("--timeout", type=int, default=None, help="Override request timeout.")
@click.option("--vulns", default=None, help="Comma-separated vulnerability list.")
@click.option("--methods", default=None, help="Comma-separated HTTP methods.")
@click.option("--chunk-size", type=int, default=None, help="Parameters per request.")
@click.pass_context
def mass_fuzz(ctx, config_path, only, resume, keep_templates, skip_fuzz, skip_nuclei,
              refresh_params, refresh_fuzz, max_hosts, rl, workers, timeout, vulns,
              methods, chunk_size):
    """Run the full fuzz pipeline over all subdomains of a target."""
    settings = _settings(ctx)
    workspace = _workspace(ctx)
    cfg = load_target_config(config_path, settings)
    cfg = _with_overrides(
        cfg,
        settings,
        rl=rl,
        c=workers,
        timeout=timeout,
        vulns=vulns,
        methods=methods,
        chunk_size=chunk_size,
    )

    options = MassFuzzOptions(
        only=list(only),
        resume=resume,
        keep_templates=keep_templates,
        skip_fuzz=skip_fuzz,
        skip_nuclei=skip_nuclei,
        refresh_params=refresh_params,
        refresh_fuzz=refresh_fuzz,
        max_hosts=max_hosts,
    )

    try:
        result = run_mass_fuzz(workspace, cfg, settings, options)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    if result.errors:
        raise click.ClickException(
            f"pipeline completed with {len(result.errors)} error(s); see output above"
        )


# ---------------------------------------------------------------------------
# single-fuzz
# ---------------------------------------------------------------------------

@cli.command("single-fuzz")
@click.argument("url")
@click.option("-c", "--config", "config_path", required=True,
              type=click.Path(exists=True, dir_okay=False), help="Target config JSON.")
@click.option("--method", type=click.Choice([m.lower() for m in VALID_METHODS]),
              default=None, help="HTTP method for body fuzzing.")
@click.option("--data", default=None, help="Request body (urlencoded or JSON).")
@click.option("--param", "params", multiple=True, help="Explicit parameter name (repeatable).")
@click.option("--content-type", type=click.Choice(list(VALID_CONTENT_TYPES)),
              default=None, help="Body content type.")
@click.option("--skip-nuclei", is_flag=True, help="Do not run nuclei.")
@click.option("--keep-templates/--no-keep-templates", default=True,
              help="Keep generated template JSONL files.")
@click.option("--rl", type=int, default=None, help="Override requests/second.")
@click.option("--workers", type=int, default=None, help="Override concurrency.")
@click.option("--timeout", type=int, default=None, help="Override request timeout.")
@click.pass_context
def single_fuzz(ctx, url, config_path, method, data, params, content_type, skip_nuclei,
                keep_templates, rl, workers, timeout):
    """Fuzz a single URL through the full pipeline."""
    settings = _settings(ctx)
    workspace = _workspace(ctx)
    cfg = load_target_config(config_path, settings)
    cfg = _with_overrides(cfg, settings, rl=rl, c=workers, timeout=timeout)

    options = SingleFuzzOptions(
        method=method.upper() if method else None,
        data=data,
        params=list(params),
        content_type=content_type,
        skip_nuclei=skip_nuclei,
        keep_templates=keep_templates,
    )

    try:
        run_single_fuzz(workspace, cfg, settings, url, options)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


# ---------------------------------------------------------------------------
# aggregate
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-t", "--target", required=True, help="Target name.")
@click.option("--format", "formats", multiple=True,
              type=click.Choice(["txt", "json", "html"]),
              help="Report format(s); defaults to all.")
@click.pass_context
def aggregate(ctx, target, formats):
    """Aggregate and report all findings for a target."""
    workspace = _workspace(ctx)
    target_paths = workspace.target(target)
    _require_target_dir(target_paths, target)
    count = aggregate_results(workspace, target, list(formats) or None)
    ui.ok(f"aggregated {count} finding(s)")
    ui.kv("output", target_paths.output)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-t", "--target", default=None, help="Target name (omit to list targets).")
@click.pass_context
def status(ctx, target):
    """Show progress and finding counts."""
    workspace = _workspace(ctx)
    if not target:
        targets = workspace.targets()
        if not targets:
            ui.warn(f"no results in {workspace.results}")
            return
        ui.step("targets")
        for name in targets:
            target_paths = workspace.target(name)
            state = State(target_paths)
            total = sum(entry.get("findings", 0) for entry in state.subdomains.values())
            ui.kv(name, f"{len(state.subdomains)} subdomain(s), {total} finding(s)")
        return

    target_paths = workspace.target(target)
    _require_target_dir(target_paths, target)
    state = State(target_paths)
    disk = disk_status(target_paths)

    ui.step(f"status — {target}")
    rows = []
    for host in sorted(disk):
        entry = state.get(host)
        info = disk[host]
        rows.append(
            (
                host,
                f"{info['passive']} urls / {info['katana']} crawled",
                f"{info['findings']} findings · {entry.get('status', 'unknown')}",
            )
        )
    if not rows:
        ui.warn("no subdomains")
        return
    ui.table(rows, ("subdomain", "recon", "findings / state"))
    total = sum(item["findings"] for item in disk.values())
    print()
    ui.kv("total findings", total)
    ui.kv("report", target_paths.output)


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-t", "--target", required=True, help="Target name.")
@click.option("--sub", default=None, help="Remove only this subdomain directory.")
@click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation.")
@click.pass_context
def clean(ctx, target, sub, yes):
    """Delete results for a target (or one subdomain)."""
    workspace = _workspace(ctx)
    target_paths = workspace.target(target)
    if not target_paths.root.is_dir():
        ui.warn(f"nothing to clean: {target_paths.root} does not exist")
        return

    destination = target_paths.sub(sub).root if sub else target_paths.root
    results_root = workspace.results.resolve()
    try:
        destination.resolve().relative_to(results_root)
    except ValueError:
        raise click.ClickException("refusing to delete outside the results directory")

    if not destination.exists():
        ui.warn(f"nothing to clean: {destination} does not exist")
        return
    if not yes:
        click.confirm(f"Permanently delete {destination}?", abort=True)
    shutil.rmtree(destination)
    ui.ok(f"deleted {destination}")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--optional/--no-optional", default=True, help="Include optional tools.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.pass_context
def doctor(ctx, optional, as_json):
    """Check external tool availability."""
    from core.process import which

    if as_json:
        payload = []
        for spec in TOOLS:
            if spec.group == "optional" and not optional:
                continue
            payload.append(
                {
                    "name": spec.name,
                    "group": spec.group,
                    "path": which(spec.name),
                    "purpose": spec.purpose,
                    "install": spec.install,
                }
            )
        click.echo(json.dumps(payload, indent=2))
        return

    ok = run_doctor(show_optional=optional)
    if not ok:
        ui.warn("some core tools are missing — passive/active recon may be degraded")


# ---------------------------------------------------------------------------
# init / validate
# ---------------------------------------------------------------------------

@cli.command("init")
@click.argument("name")
@click.option("--seed", "seeds", multiple=True, help="Seed URL(s) for the target.")
@click.option("--force", is_flag=True, help="Overwrite an existing config.")
@click.pass_context
def init_target(ctx, name, seeds, force):
    """Create a starter target config in target-configs/."""
    filename = safe_component(name)
    path = project_root() / "target-configs" / f"{filename}.json"
    if path.exists() and not force:
        raise click.ClickException(f"{path} already exists (use --force to overwrite)")
    write_sample_config(path, filename, list(seeds) or None)
    ui.ok(f"created {path}")
    ui.info(f"edit it, then run: ./reconx mass-fuzz -c {path}")


@cli.command("validate")
@click.argument("config_path", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def validate(ctx, config_path):
    """Validate a target config file and print the normalised result."""
    settings = _settings(ctx)
    cfg = load_target_config(config_path, settings)
    click.echo(json.dumps(cfg.to_dict(), indent=2))
    ui.ok("config is valid")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        cli.main(standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        raise SystemExit(exc.exit_code)
    except click.Abort:
        ui.warn("aborted")
        raise SystemExit(130)
    except (ConfigError, ValueError) as exc:
        ui.error(str(exc))
        raise SystemExit(2)
    except KeyboardInterrupt:
        ui.warn("interrupted")
        raise SystemExit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
