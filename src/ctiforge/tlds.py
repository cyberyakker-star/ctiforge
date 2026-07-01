"""A small bundled set of common/plausible TLDs.

Not the full IANA list — deliberately slim. Its job is to kill the classic
false positives (``example.py``, ``config.yaml``, ``README.md``) while keeping
the domains that actually appear in threat reports. Extend as needed.
"""

from __future__ import annotations

# Common gTLDs, country codes, and TLDs frequently seen in CTI reports.
KNOWN_TLDS: frozenset[str] = frozenset(
    {
        # generic
        "com", "net", "org", "info", "biz", "gov", "edu", "mil", "int",
        "io", "co", "app", "dev", "xyz", "online", "site", "top", "club",
        "shop", "store", "cloud", "tech", "space", "live", "life", "world",
        "pro", "name", "mobi", "asia", "tv", "cc", "me", "ai", "so", "us",
        "email", "click", "link", "download", "run", "host",
        "website", "digital", "systems", "network", "solutions", "agency",
        # country codes commonly abused / referenced
        "ru", "cn", "kp", "ir", "ua", "uk", "de", "fr", "nl", "pl", "br",
        "in", "jp", "kr", "au", "ca", "es", "it", "se", "no", "fi", "dk",
        "ch", "at", "be", "cz", "ro", "tr", "gr", "pt", "hu", "sk", "bg",
        "za", "ng", "eg", "sa", "ae", "il", "vn", "th", "id", "my", "sg",
        "ph", "tw", "hk", "mx", "ar", "cl", "pe", "ve", "by", "kz", "ge",
        "am", "az", "md", "lv", "lt", "ee", "rs", "hr", "si", "ba", "mk",
        "su", "cx", "ws", "tk", "ml", "ga", "cf", "gq", "pw", "cat",
    }
)

# Real TLDs that are also common file extensions ("backup.zip", "lure.mov").
# A bare word ending in one of these is far more likely a filename than a
# domain, so bare-domain extraction rejects them; URL/email hosts (where a
# scheme or @ disambiguates) still accept them.
FILE_EXTENSION_TLDS: frozenset[str] = frozenset({"zip", "mov"})

# NOTE: RFC 2606 reserved TLDs (.example, .test, .invalid) are deliberately
# NOT plausible: reports use them for sanitized placeholder values, which must
# never be exported as blocklist-ready indicators.


def has_plausible_tld(domain: str, *, allow_file_extension_tlds: bool = True) -> bool:
    """Return True if the domain's final label is a known/plausible TLD."""
    domain = domain.strip().rstrip(".").lower()
    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if not allow_file_extension_tlds and tld in FILE_EXTENSION_TLDS:
        return False
    return tld in KNOWN_TLDS or tld in FILE_EXTENSION_TLDS
