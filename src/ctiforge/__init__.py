"""ctiforge — report-to-structured-intel conversion with hallucination guards."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ctiforge")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0.0.0.dev0"
