"""URL parsing, normalisation and scope utilities.

The functions here deliberately avoid third-party dependencies so they are
usable from tests and from the passive/active modules alike.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_STATIC_EXTENSIONS = (
    ".json", ".js", ".mjs", ".css", ".scss", ".map", ".fnt", ".ogg", ".jpg",
    ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf",
    ".doc", ".docx", ".ogv", ".webm", ".wmv", ".webp", ".mov", ".mp3", ".m4a",
    ".m4p", ".ppt", ".pptx", ".tif", ".tiff", ".ttf", ".otf", ".woff",
    ".woff2", ".bmp", ".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf",
    ".txt", ".xml", ".zip", ".gz", ".tar", ".rar", ".7z", ".apk", ".dmg",
    ".iso", ".woff", ".wasm", ".map", ".mpg", ".mpeg", ".avi", ".webmanifest",
)

_SAFE_SCHEMES = {"http", "https"}
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_MAX_URL_LENGTH = 8192


# ---------------------------------------------------------------------------
# Host helpers
# ---------------------------------------------------------------------------

def parse_host(value: str) -> str:
    """Extract a host (optionally ``host:port``) from a URL or bare domain.

    >>> parse_host("https://App.Example.com/path?q=1")
    'app.example.com'
    >>> parse_host("example.com:8443")
    'example.com:8443'
    """
    value = (value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        if value.startswith("//"):
            value = "https:" + value
        else:
            value = "http://" + value
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").strip().lower().rstrip(".")
        if not host:
            return ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return host
    except ValueError:
        return ""


def hostname(url: str) -> str:
    """Return the hostname (without port) of *url*."""
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def netloc(url: str) -> str:
    """Return the lower-cased network location (host + port) of *url*."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.port:
            return f"{host}:{parts.port}"
        return host
    except ValueError:
        return ""


def is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return parts.scheme.lower() in _SAFE_SCHEMES and bool(parts.hostname)
    except ValueError:
        return False


def base_url(url: str) -> str:
    """Return *url* without query string or fragment."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def host_root(url: str) -> str:
    """Return the scheme and host of *url* (no path)."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def join(base: str, path: str) -> str:
    return urljoin(base, path)


def in_scope(url: str, domains: list[str] | tuple[str, ...]) -> bool:
    """True when *url* belongs to one of *domains* (or no scope is given)."""
    if not domains:
        return True
    host = hostname(url)
    if not host:
        return False
    for domain in domains:
        domain = (domain or "").strip().lower().lstrip(".").rstrip(".")
        if not domain:
            continue
        if host == domain or host.endswith("." + domain):
            return True
    return False


def root_domain_guess(host: str) -> str:
    """Best-effort registrable domain for scope handling.

    This intentionally does not try to be a full public-suffix implementation;
    callers can always provide an explicit ``scope_domains`` list.
    """
    host = (host or "").lower().split(":")[0].strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    # Common two-level public suffixes.
    if labels[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# URL normalisation / filtering
# ---------------------------------------------------------------------------

def normalize_url(url: str, *, normalize_query: bool = True) -> str | None:
    """Return a canonical form of *url*, or ``None`` when it is unusable.

    * fragments and userinfo are dropped
    * host names are lower-cased
    * default ports are removed
    * query parameters are sorted by name (when ``normalize_query``)
    """
    if not url:
        return None
    url = url.strip()
    if not url or len(url) > _MAX_URL_LENGTH or _CONTROL_RE.search(url):
        return None
    if url.startswith("//"):
        url = "https:" + url
    if "://" not in url:
        return None

    try:
        parts = urlsplit(url)
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in _SAFE_SCHEMES:
        return None

    try:
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None

    # IDNA-encode non-ASCII host names.
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"

    path = parts.path or "/"
    # Do not let a trailing slash explosion create duplicates such as ////
    while "//" in path:
        path = path.replace("//", "/")

    query = parts.query
    if normalize_query and query:
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
            pairs.sort(key=lambda kv: (kv[0], kv[1]))
            query = urlencode(pairs, doseq=False)
        except Exception:
            pass

    return urlunsplit((scheme, netloc, path, query, ""))


def is_static_asset(url: str, extensions: tuple[str, ...] | list[str] = DEFAULT_STATIC_EXTENSIONS) -> bool:
    """True when the URL path ends in a known static-asset extension."""
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return True
    for ext in extensions:
        ext = ext if ext.startswith(".") else "." + ext
        if path.endswith(ext):
            return True
    return False


def should_keep_url(
    url: str,
    *,
    extensions: tuple[str, ...] | list[str] = DEFAULT_STATIC_EXTENSIONS,
    exclude_patterns: tuple[str, ...] | list[str] = (),
) -> bool:
    """Apply the standard passive-recon URL filter."""
    if not is_http_url(url):
        return False
    if is_static_asset(url, extensions):
        return False
    for pattern in exclude_patterns:
        try:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        except re.error:
            continue
    return True


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

def query_pairs(url: str) -> list[tuple[str, str]]:
    """Return ``(name, value)`` pairs from the URL query string."""
    try:
        return parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []


def query_params(url: str) -> list[str]:
    """Return unique query parameter names in order of appearance."""
    seen: set[str] = set()
    result: list[str] = []
    for name, _ in query_pairs(url):
        if name and name not in seen:
            seen.add(name)
            result.append(name)
    return result


def query_samples(url: str) -> dict[str, str]:
    """Return the first observed value for every query parameter."""
    samples: dict[str, str] = {}
    for name, value in query_pairs(url):
        if name and name not in samples:
            samples[name] = value
    return samples


def add_query(url: str, params: dict[str, str] | list[tuple[str, str]]) -> str:
    """Return *url* with *params* appended/merged."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    pairs.extend(params.items() if isinstance(params, dict) else params)
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, doseq=False), ""))


def url_without_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
