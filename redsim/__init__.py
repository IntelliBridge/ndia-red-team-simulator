from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("redsim-platform")
except PackageNotFoundError:  # pragma: no cover - source tree without dist metadata
    __version__ = "0.13.0"
