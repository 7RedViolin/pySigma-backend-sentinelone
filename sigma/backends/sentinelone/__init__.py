from .sentinelone import SentinelOneBackend
from importlib.metadata import version, PackageNotFoundError

backends = {
    "sentinelone": SentinelOneBackend,
}

try:
    __version__ = version("pySigma-backend-sentinelone")
except PackageNotFoundError:
    # package is not installed
    __version__ = "0.0.0"