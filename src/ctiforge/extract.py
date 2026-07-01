"""Stage 2 — deterministic IOC extraction, refang, validation, dedupe.

The LLM is never the source of truth for indicator values. Everything here is
plain code: regex (via iocextract) plus our own validation layer.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import iocextract

from .models import Indicator, IndicatorType
from .tlds import has_plausible_tld

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


def _classify_hash(value: str) -> IndicatorType | None:
    if _MD5_RE.match(value):
        return "md5"
    if _SHA1_RE.match(value):
        return "sha1"
    if _SHA256_RE.match(value):
        return "sha256"
    return None


def _valid_ip(value: str, include_private: bool) -> IndicatorType | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not include_private and (
        ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return None
    return "ipv4" if ip.version == 4 else "ipv6"


def _refang_text(text: str) -> str:
    """Return a copy of the text with common defang markers normalized."""
    out = re.sub(r"h(?:xx|XX|tt)ps?(?=\[?:?/?/?)", lambda m: m.group(0).replace("xx", "tt"), text)
    out = re.sub(r"\bh(?:xx|XX)p", "http", out)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    out = re.sub(r"\[dot\]|\(dot\)|\s+dot\s+", ".", out, flags=re.IGNORECASE)
    out = out.replace("[://]", "://").replace("[:]", ":").replace("[/]", "/")
    out = out.replace("[@]", "@").replace("(@)", "@")
    out = re.sub(r"\[at\]|\(at\)", "@", out, flags=re.IGNORECASE)
    return out


def _find_original(value: str, text: str) -> str | None:
    """Locate the (possibly defanged) source form of ``value`` in the text.

    Returns the original substring only if it differs from the refanged value.
    """
    if value in text:
        return None
    dot = r"(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\.)"
    pattern = ""
    for ch in value:
        if ch == ".":
            pattern += dot
        elif ch == "@":
            pattern += r"(?:\[@\]|\(@\)|\[at\]|@)"
        else:
            pattern += re.escape(ch)
    # allow hxxp defang of the scheme
    pattern = pattern.replace(re.escape("http"), r"h(?:xx|tt)p")
    m = re.search(pattern, text, flags=re.IGNORECASE)
    if m and m.group(0) != value:
        return m.group(0)
    return None


def _domain_from_url(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host


def extract_indicators(text: str, include_private: bool = False) -> list[Indicator]:
    """Extract, refang, validate and dedupe indicators from report text.

    Deduplication is case-insensitive. ``defanged_original`` is preserved when
    the source form differed from the refanged value.
    """
    found: dict[tuple[str, str], Indicator] = {}
    url_hosts: set[str] = set()

    def add(value: str, itype: IndicatorType) -> None:
        key = (itype, value.lower())
        if key in found:
            return
        found[key] = Indicator(
            value=value,
            type=itype,
            defanged_original=_find_original(value, text),
        )

    # Build a fully refanged copy of the text for regex-based extraction.
    norm = _refang_text(text)

    # URLs — require an explicit scheme so bare defanged hosts don't become URLs.
    for m in re.finditer(r"\bhttps?://[^\s<>\"'\])}]+", norm, flags=re.IGNORECASE):
        u = m.group(0).rstrip(".,;:!?)]}>'\"")
        host = _domain_from_url(u)
        if host is None:
            continue
        if _valid_ip(host, include_private=True) is None and not has_plausible_tld(host):
            continue
        url_hosts.add(host.lower())
        add(u, "url")

    # IPs — own regexes; iocextract's IP extractor is unreliable with adjacency.
    for m in re.finditer(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", norm):
        itype = _valid_ip(m.group(0), include_private)
        if itype is not None:
            add(m.group(0), itype)
    for m in re.finditer(r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])", norm):
        itype = _valid_ip(m.group(0), include_private)
        if itype == "ipv6":
            add(str(ipaddress.ip_address(m.group(0))), itype)

    # Emails (before domains, so their host isn't double-counted as a domain).
    email_hosts: set[str] = set()
    for m in re.finditer(r"\b[a-zA-Z0-9._%+-]+@((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})\b", norm):
        e = m.group(0).lower()
        host = m.group(1).lower()
        if not has_plausible_tld(host):
            continue
        email_hosts.add(host)
        add(e, "email")

    # Domains — regex scan validated against the plausible-TLD check.
    for m in re.finditer(r"(?<![@/\w])((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})\b", norm):
        cand = m.group(1).rstrip(".").lower()
        if not _DOMAIN_RE.match(cand) or not has_plausible_tld(cand):
            continue
        if cand in url_hosts or cand in email_hosts:
            continue
        add(cand, "domain")

    # Hashes
    for h in iocextract.extract_hashes(norm):
        itype = _classify_hash(h.strip())
        if itype:
            add(h.strip().lower(), itype)

    return list(found.values())
