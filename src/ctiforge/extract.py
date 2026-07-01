"""Stage 2 — deterministic IOC extraction, refang, validation, dedupe.

The LLM is never the source of truth for indicator values. Everything here is
plain code: regex (iocextract for hashes) plus our own validation layer.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import iocextract

from .models import Indicator, IndicatorType
from .tlds import has_plausible_tld

# One hostname grammar, composed into every regex that needs it, so the
# email/domain/validation patterns cannot drift apart.
_HOST = r"(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_HOST}$")

_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_HASH_LENGTHS: dict[int, IndicatorType] = {32: "md5", 40: "sha1", 64: "sha256"}

# Defang markers: canonical form -> regex alternatives seen in the wild.
# BOTH the forward normalizer (_refang_text) and the reverse provenance search
# (_find_original) are derived from this single table so they cannot drift.
# Deliberately NOT included: prose forms like " dot " — replacing the English
# word "dot" fabricates indicators out of ordinary sentences.
_DEFANG_FORMS: dict[str, list[str]] = {
    "://": [r"\[://\]"],
    ".": [r"\[\.\]", r"\(\.\)", r"\{\.\}", r"\[dot\]", r"\(dot\)"],
    "@": [r"\[@\]", r"\(@\)", r"\[at\]", r"\(at\)"],
    ":": [r"\[:\]"],
    "/": [r"\[/\]"],
}
_SCHEME_RE = re.compile(r"\bh(?:xx|XX)ps?\b|\bh(?:xx|XX)p\b")


def _classify_hash(value: str) -> IndicatorType | None:
    if _HEX_RE.match(value):
        return _HASH_LENGTHS.get(len(value))
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
    out = _SCHEME_RE.sub(lambda m: m.group(0).replace("xx", "tt").replace("XX", "tt"), text)
    for canonical, forms in _DEFANG_FORMS.items():
        out = re.sub("|".join(forms), canonical, out, flags=re.IGNORECASE)
    return out


def _defang_alternation(canonical: str) -> str:
    """Regex matching a canonical char/sequence or any of its defanged forms."""
    forms = _DEFANG_FORMS.get(canonical, [])
    return "(?:" + "|".join([*forms, re.escape(canonical)]) + ")"


def _find_original(value: str, text: str) -> str | None:
    """Locate the (possibly defanged) source form of ``value`` in the text.

    Returns the original substring only if it was actually defanged — pure
    case variance does not count. Values containing no defang-able characters
    (e.g. hashes) are skipped outright.
    """
    if not any(c in value for c in ".@:/"):
        return None
    if value in text:
        return None
    parts: list[str] = []
    i = 0
    while i < len(value):
        if value.startswith("://", i):
            # '[://]' defangs three chars at once; also allow per-char forms.
            parts.append(
                "(?:" + _DEFANG_FORMS["://"][0] + "|"
                + _defang_alternation(":") + _defang_alternation("/") * 2 + ")"
            )
            i += 3
        elif value[i] in _DEFANG_FORMS:
            parts.append(_defang_alternation(value[i]))
            i += 1
        else:
            parts.append(re.escape(value[i]))
            i += 1
    pattern = "".join(parts)
    # allow hxxp defang of the scheme
    pattern = pattern.replace(re.escape("http"), r"h(?:xx|tt)p")
    m = re.search(pattern, text, flags=re.IGNORECASE)
    if m and m.group(0).lower() != value.lower():
        return m.group(0)
    return None


def _domain_from_url(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host


def _strip_url_trailing(url: str) -> str:
    """Strip trailing punctuation, keeping parens that are balanced in the URL."""
    while url:
        last = url[-1]
        if last in ".,;:!?]}>'\"":
            url = url[:-1]
        elif last == ")" and url.count("(") < url.count(")"):
            url = url[:-1]
        else:
            break
    return url


def extract_indicators(text: str, include_private: bool = False) -> list[Indicator]:
    """Extract, refang, validate and dedupe indicators from report text.

    Deduplication is case-insensitive. ``defanged_original`` is preserved when
    the source form was actually defanged.
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

    # URLs — require an explicit scheme so bare defanged hosts don't become
    # URLs. ')' is allowed in the match so paths like /Emotet_(malware) stay
    # intact; _strip_url_trailing removes only unbalanced trailing parens.
    for m in re.finditer(r"\bhttps?://[^\s<>\"'\]}]+", norm, flags=re.IGNORECASE):
        u = _strip_url_trailing(m.group(0))
        host = _domain_from_url(u)
        if host is None:
            continue
        if _valid_ip(host, include_private=True) is None and not has_plausible_tld(host):
            continue
        url_hosts.add(host.lower())
        add(u, "url")

    # IPs — own regexes; iocextract's IP extractor is unreliable with adjacency.
    # The dotted-continuation guards reject 4-octet slices of longer dotted
    # strings such as version numbers ("build 185.2.3.4.1").
    for m in re.finditer(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)", norm):
        itype = _valid_ip(m.group(0), include_private)
        if itype is not None:
            add(m.group(0), itype)
    for m in re.finditer(r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])", norm):
        itype = _valid_ip(m.group(0), include_private)
        if itype == "ipv6":
            add(str(ipaddress.ip_address(m.group(0))), itype)

    # Emails
    for m in re.finditer(rf"\b[a-zA-Z0-9._%+-]+@({_HOST})\b", norm):
        host = m.group(1).lower()
        if has_plausible_tld(host):
            add(m.group(0).lower(), "email")

    # Domains — regex scan validated against the plausible-TLD check. The
    # lookbehind excludes '@', '/', '.', '-' and word chars so we never capture
    # a partial label from inside a URL or email host. Bare domains reject
    # filename-collision TLDs (.zip, .mov) — those need a scheme to count.
    for m in re.finditer(rf"(?<![@/\w.-])({_HOST})\b", norm):
        cand = m.group(1).rstrip(".").lower()
        if not _DOMAIN_RE.match(cand):
            continue
        if not has_plausible_tld(cand, allow_file_extension_tlds=False):
            continue
        if cand in url_hosts:
            continue
        add(cand, "domain")

    # Hashes
    for h in iocextract.extract_hashes(norm):
        itype = _classify_hash(h.strip())
        if itype:
            add(h.strip().lower(), itype)

    return list(found.values())
