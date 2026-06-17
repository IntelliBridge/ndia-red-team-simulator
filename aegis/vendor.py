"""Submodule mirror URL rewriting for air-gapped installs.

Aegis vendors several upstream repos as git submodules (CAI, Strix, the
MCP Kali server, …). Behind an air-gap those can't be fetched from
``github.com`` / ``gitlab.com``; instead an internal mirror serves the same
``<org>/<repo>.git`` paths under a single host.

This module is intentionally **pure** — no I/O, no git invocation — so the
rewrite rules are trivially testable. ``scripts/vendor-submodules.sh`` does
the actual ``git submodule set-url`` plumbing using the same mapping.

Rewrite rules (``mirror_url``):

- HTTPS form ``https://github.com/org/repo.git`` →
  ``https://<host>/org/repo.git`` (scheme + original host dropped, path kept).
- SCP-like SSH form ``git@github.com:org/repo.git`` →
  ``https://<host>/org/repo.git`` (the ``user@host:`` prefix is dropped).
- A trailing ``.git`` is normalised back on exactly once, whether or not the
  original URL carried one.
- Deeply nested paths (``org/sub/repo``) are preserved verbatim.
"""

from __future__ import annotations

import configparser
import re


def _strip_to_path(original_url: str) -> str:
    """Reduce a git remote URL to its ``org/repo`` path, sans scheme/host.

    Handles the two forms that appear in ``.gitmodules``:

    - ``scheme://host[:port]/org/repo[.git]`` (http, https, ssh, git)
    - SCP-like ``[user@]host:org/repo[.git]``
    """
    url = original_url.strip()

    # scheme://host/path  (http, https, ssh, git, …)
    scheme_match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)/(.+)$", url)
    if scheme_match:
        return scheme_match.group(2)

    # SCP-like: [user@]host:path  (no scheme, single ':' before the path).
    scp_match = re.match(r"^[^/]+@?[^/:]+:(.+)$", url)
    if scp_match:
        return scp_match.group(1)

    # Already a bare path — return as-is.
    return url


def mirror_url(original_url: str, host: str) -> str:
    """Rewrite a submodule URL to fetch from the internal mirror ``host``.

    The ``<org>/<repo>`` path is preserved and re-rooted under ``host`` as an
    HTTPS URL with a single trailing ``.git``::

        mirror_url("https://github.com/aliasrobotics/cai.git", "mirror.int")
        # -> "https://mirror.int/aliasrobotics/cai.git"

        mirror_url("git@github.com:usestrix/strix.git", "mirror.int")
        # -> "https://mirror.int/usestrix/strix.git"

    ``host`` may include a scheme and/or trailing slashes; both are normalised
    away so the result is always ``https://<bare-host>/<path>.git``.
    """
    path = _strip_to_path(original_url)

    # Normalise an existing ``.git`` suffix so we add it back exactly once.
    if path.endswith(".git"):
        path = path[: -len(".git")]
    path = path.strip("/")

    # Allow the host to be passed with a scheme or trailing slash.
    bare_host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", host).strip("/")

    return f"https://{bare_host}/{path}.git"


def submodule_mirror_map(gitmodules_text: str, host: str) -> dict[str, str]:
    """Parse ``.gitmodules`` text and return ``{original_url: mirrored_url}``.

    One entry per ``[submodule "…"]`` section that declares a ``url``. The
    keys are the verbatim original URLs; the values are their mirror
    rewrites via :func:`mirror_url`.
    """
    parser = configparser.ConfigParser()
    parser.read_string(gitmodules_text)

    mapping: dict[str, str] = {}
    for section in parser.sections():
        if not section.startswith("submodule"):
            continue
        original = parser[section].get("url")
        if not original:
            continue
        mapping[original] = mirror_url(original, host)
    return mapping
