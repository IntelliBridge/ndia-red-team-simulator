from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aegis-platform")
except PackageNotFoundError:  # pragma: no cover - source tree without dist metadata
    __version__ = "0.11.0"
