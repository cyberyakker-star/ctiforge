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
- **`requests` dependency**: added explicitly because `iocextract` imports it at
  module load but under-declares it in its own metadata (CI installed iocextract
  without pulling requests, breaking `import iocextract`). Not a new functional
  dependency — it just makes the brief-approved iocextract importable.

## Post-review decisions (in-depth code review)

- **Evidence grounding enforced in code**: each ATT&CK mapping's evidence
  sentence must be found (casefold, whitespace-collapsed) in the report text
  or its refanged copy; otherwise the mapping moves to `rejected_mappings`
  with reason "evidence sentence not found verbatim in the report".
- **Defang knowledge unified**: a single `_DEFANG_FORMS` table drives both the
  forward normalizer and the reverse provenance search so they cannot drift.
  The prose form `" dot "` was removed entirely — replacing the English word
  "dot" fabricated indicators from ordinary sentences.
- **TLD policy tightened**: RFC 2606 placeholders (.example/.test/.invalid)
  are rejected outright (sanitized placeholders must never become blocklist
  entries); filename-collision TLDs (.zip/.mov) are rejected for bare domains
  but accepted as URL/email hosts where a scheme or @ disambiguates.
- **Chunked-analysis audit trail**: technique IDs in per-chunk partials are
  validated before the merge call so hallucinated IDs the merge model drops
  still surface in `rejected_mappings`.
- **Truncation is an error**: `stop_reason == "max_tokens"` fails loudly
  instead of being misdiagnosed as bad JSON (limit raised to 8192).
- **Stale-cache fallback**: if the ATT&CK refresh download fails but a
  previously downloaded dataset exists, ctiforge warns and uses the stale
  copy instead of aborting. A slim derived-index cache (`attack-index.json`,
  keyed on the dataset file's mtime+size) avoids re-parsing the ~45 MB STIX
  bundle on every run.
- **Known, accepted gap**: indicator values the LLM embeds in *prose* fields
  (summary, behavior, evidence text) are not scanned/redacted — the drop
  guard applies to the structured `indicator_context` list. Prose-level
  redaction is an inherent limitation; the review banner covers it.
- **iocextract kept** (used for hash extraction only) because the brief
  mandates it; dropping it (and the `requests` pin) in favor of a local hex
  regex is a candidate simplification for v0.2 — flagged, not applied.
