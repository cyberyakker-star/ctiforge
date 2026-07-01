# Decisions

Ambiguity resolutions and notable choices made while building ctiforge v0.1.

- **Build backend**: `hatchling` (simple, no extra config) rather than setuptools.
- **Bundled TLD check**: a slim hand-curated set in `tlds.py` (common gTLDs +
  country codes + CTI-relevant TLDs) instead of pulling the full public-suffix
  list. Its only job is killing false positives like `example.py`/`report.pdf`.
- **IOC extraction**: `iocextract` is used for hashes; IPs, URLs, domains and
  emails are extracted with our own regexes over a refanged copy of the text,
  because iocextract's IP extractor drops adjacent IPs and synthesizes URLs
  from bare defanged hosts. Refanging is done by a small local normalizer.
- **URLs require an explicit scheme** so bare defanged hosts become `domain`
  indicators, not `url` indicators.
- **defanged_original** is recorded only when the source form differed from the
  refanged value, located by a tolerant regex over the original text.
- **CSV `confidence` column**: indicator-level confidence is not produced by the
  model (confidence attaches to techniques), so the column is emitted as `n/a`.
- **Model default** kept as `claude-sonnet-4-6` per the brief (not relitigated).
