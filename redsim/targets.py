"""Vulnerable-target orchestration (Juice Shop, DVWA) via Docker.

Two modes:
- image mode: run a pinned upstream image, no patching possible.
- source mode: build a local image from the user's repo, then run it; allows
  patch -> rebuild -> restart for verification against a real running target.

Every Docker mutation is routed through subprocess.run so tests can mock it
cleanly. All state goes into TargetRuntime, which is persisted to
``<run_path>/target/runtime.json``.
"""

from __future__ import annotations

import atexit
import json
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.error import URLError
from urllib.request import urlopen

if TYPE_CHECKING:
    from types import FrameType


@dataclass
class TargetRuntime:
    name: str
    mode: str                      # "image" | "source"
    url: str
    container_name: str
    container_id: str | None = None
    image_tag: str | None = None
    source_repo: str | None = None
    source_ref_before: str | None = None
    source_ref_after: str | None = None
    built_image_digest: str | None = None
    started_at: str | None = None
    ready_at: str | None = None
    last_rebuild_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
    )


def _git_head(repo: Path) -> str | None:
    try:
        return _run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


class TargetPack:
    """Base class for a vulnerable target."""

    name: ClassVar[str] = "abstract"
    default_port: ClassVar[int] = 3000
    container_port: ClassVar[int] = 3000
    image: ClassVar[str] = ""           # pinned upstream image
    container_prefix: ClassVar[str] = "redsim-target"
    readiness_path: ClassVar[str] = "/"
    readiness_marker: ClassVar[str | None] = None

    def __init__(self, run_path: Path | None = None, port: int | None = None):
        self.run_path = run_path
        self.port = port or self.default_port
        # Run-scoped container names prevent collisions between concurrent
        # runs (and between this run and a leftover container from a prior
        # crash). When run_path is None (ad-hoc / tests) we fall back to the
        # static prefix.
        scope = run_path.name if run_path is not None else "adhoc"
        self.container_name = f"{self.container_prefix}-{scope}"
        self.runtime = TargetRuntime(
            name=self.name,
            mode="image",
            url=f"http://localhost:{self.port}",
            container_name=self.container_name,
        )
        self._cleanup_registered = False

    @property
    def url(self) -> str:
        return self.runtime.url

    def _register_cleanup(self) -> None:
        if self._cleanup_registered:
            return
        self._cleanup_registered = True
        atexit.register(self._cleanup_silent)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass

    def _signal_handler(self, signum: int, frame: FrameType | None) -> None:  # noqa: ARG002
        self._cleanup_silent()

    def _cleanup_silent(self) -> None:
        try:
            self.down()
        except Exception:
            pass

    def _remove_existing(self) -> None:
        _run(["docker", "rm", "-f", self.container_name], check=False)

    def _run_container(self, image: str) -> str:
        self._remove_existing()
        result = _run([
            "docker", "run", "-d",
            "--name", self.container_name,
            "-p", f"{self.port}:{self.container_port}",
            image,
        ])
        return result.stdout.strip()

    def _image_digest(self, image: str) -> str | None:
        try:
            result = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
            return result.stdout.strip() or None
        except subprocess.CalledProcessError:
            return None

    def up(self, *, image_tag: str | None = None) -> TargetRuntime:
        """Run the target from a pinned upstream image."""
        image = image_tag or self.image
        if not image:
            raise ValueError(f"No image configured for target '{self.name}'")
        self.runtime.mode = "image"
        self.runtime.image_tag = image
        self.runtime.started_at = _now_iso()
        self.runtime.container_id = self._run_container(image)
        self.runtime.built_image_digest = self._image_digest(image)
        self._register_cleanup()
        self._persist_runtime()
        return self.runtime

    def up_from_repo(self, repo_path: Path | str) -> TargetRuntime:
        """Build a local image from the repo and run it."""
        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            raise FileNotFoundError(f"Repo path does not exist: {repo}")
        image_tag = f"redsim-{self.name}:local"
        _run(["docker", "build", "-t", image_tag, str(repo)])
        self.runtime.mode = "source"
        self.runtime.image_tag = image_tag
        self.runtime.source_repo = str(repo)
        self.runtime.source_ref_before = _git_head(repo)
        self.runtime.source_ref_after = self.runtime.source_ref_before
        self.runtime.started_at = _now_iso()
        self.runtime.container_id = self._run_container(image_tag)
        self.runtime.built_image_digest = self._image_digest(image_tag)
        self._register_cleanup()
        self._persist_runtime()
        return self.runtime

    def rebuild(self, repo_path: Path | str) -> TargetRuntime:
        """Rebuild the source-mode image and restart the container."""
        if self.runtime.mode != "source":
            raise RuntimeError("rebuild() is only valid in source mode; use up_from_repo() first")
        repo = Path(repo_path).resolve()
        image_tag = self.runtime.image_tag or f"redsim-{self.name}:local"
        _run(["docker", "build", "-t", image_tag, str(repo)])
        self.runtime.source_ref_after = _git_head(repo)
        self.runtime.last_rebuild_at = _now_iso()
        self.runtime.built_image_digest = self._image_digest(image_tag)
        self.runtime.container_id = self._run_container(image_tag)
        self._persist_runtime()
        return self.runtime

    def restart(self) -> None:
        _run(["docker", "restart", self.container_name])

    def wait_ready(self, *, timeout: float = 120.0, interval: float = 2.0) -> bool:
        url = f"{self.runtime.url}{self.readiness_path}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urlopen(url, timeout=3) as resp:
                    if resp.status == 200:
                        body = b""
                        if self.readiness_marker is not None:
                            body = resp.read(4096)
                        if self.readiness_marker is None or self.readiness_marker.encode() in body:
                            self.runtime.ready_at = _now_iso()
                            self._persist_runtime()
                            return True
            except (URLError, OSError):
                pass
            time.sleep(interval)
        return False

    def down(self) -> None:
        _run(["docker", "rm", "-f", self.container_name], check=False)

    def _persist_runtime(self) -> None:
        if self.run_path is None:
            return
        target_dir = self.run_path / "target"
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "runtime.json").write_text(json.dumps(self.runtime.to_dict(), indent=2))


class JuiceShopPack(TargetPack):
    name = "juice-shop"
    default_port = 3000
    container_port = 3000
    image = "bkimminich/juice-shop:v17.3.0"
    container_prefix = "redsim-juice-shop"
    readiness_path = "/"
    readiness_marker = "OWASP Juice Shop"


class DvwaPack(TargetPack):
    name = "dvwa"
    default_port = 3001
    container_port = 80
    # Pin a known-good tag. PLAN.md §10 explicitly rejects floating ``:latest``
    # for demo targets — drift in the upstream image quietly breaks reproducibility.
    image = "vulnerables/web-dvwa:1.10"
    container_prefix = "redsim-dvwa"
    readiness_path = "/login.php"
    readiness_marker = "Damn Vulnerable Web Application"


_REGISTRY = {
    "juice-shop": JuiceShopPack,
    "juice_shop": JuiceShopPack,
    "dvwa": DvwaPack,
}


def get_target_pack(name: str, *, run_path: Path | None = None, port: int | None = None) -> TargetPack:
    try:
        cls = _REGISTRY[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown target pack: {name}. Available: {sorted(set(_REGISTRY))}"
        ) from exc
    return cls(run_path=run_path, port=port)


def list_target_packs() -> list[str]:
    return sorted({cls.name for cls in _REGISTRY.values()})
