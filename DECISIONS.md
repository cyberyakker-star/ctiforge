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

## Interfaces (MCP + REST + web UI)

- **One shared pipeline** (`pipeline.py`: `analyze_source` / `analyze_text` /
  `get_index`) backs the CLI, MCP server and REST API, so the ingest → extract
  → validate → analyze sequence exists in exactly one place. `render.py` gained
  `analysis_to_{json,markdown,csv}()` string helpers (the file writers now wrap
  them) so the API can return rendered artifacts without temp files.
- **Three interfaces, all optional extras** so the core install stays lean:
  `ctiforge[mcp]`, `ctiforge[server]`, `ctiforge[all]`. New deps (`mcp`,
  `fastapi`, `uvicorn`, `python-multipart`) live only in those extras.
- **MCP tool split by cost/trust**: `extract_iocs` and
  `validate_attack_technique` are free/deterministic/keyless; `analyze_report`
  is the paid full pipeline, with the cost/latency called out in its docstring
  so agents invoke it deliberately.
- **Web UI is a single vanilla-JS page** served by FastAPI (no build step) so
  CI stays Python-only (ruff + pytest). It foregrounds the rejected-mappings and
  dropped-indicators appendices — the guards are the selling point.
- **API runs synchronously** and binds to `127.0.0.1`, using the server's own
  `ANTHROPIC_API_KEY`. A background-job queue for large PDFs and auth for hosted
  deployments are deferred (documented in the roadmap), keeping the local,
  single-user default simple and avoiding shared-key/cost-attribution risk.

## IOC Triage Dashboard

- **Demo-first, key-optional**: the dashboard auto-loads a bundled sample
  analysis (`web/sample_analysis.json`) via `GET /api/demo`, so the full ATT&CK
  matrix and every panel render with **no API key** — the intended path for
  demos/portfolio viewing. Live IOC extraction (`/api/extract`) is also keyless;
  only the LLM-backed full analysis needs a key.
- **Sample data is clearly labeled**, uses real ATT&CK IDs/tactics (so the matrix
  is accurate), and deliberately includes two rejected mappings and one dropped
  indicator so the hallucination guards are visible. Its `indicator_context`
  values are all present in `indicators` (a test enforces this invariant).
- **ATT&CK matrix** is a client-side render over `TechniqueMapping.tactics`
  (already in the analysis): 14 enterprise tactics as columns, techniques placed
  under each of their tactics as chips colored by confidence. No new backend.
- **Single self-contained HTML page**, vanilla JS, no build step (CI stays
  Python-only). Verified via headless Chromium screenshot + a click-through of
  the live Extract path.
