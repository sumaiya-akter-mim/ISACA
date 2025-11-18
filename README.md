# iSACA: Integrated Security Audit Chain Analyzer

An open-source, multi-faceted analyzer that correlates Dynamic (DAST), Static (SAST), and Data-Dump audits to uncover high-risk exploit chains such as SQL Injection leading to weakly stored passwords. Produces a single, actionable report linking vulnerable web parameters, insecure code lines, and weak hash formats.

## Features
- DAST: Lightweight web scanner to detect error/time-based SQL Injection indicators.
- SAST: AST-based parser for Python to detect insecure password storage (md5/sha1/plain) and unsafe SQL construction.
- Dump Audit: Hash identifier to classify password hash formats and severities (e.g., CRITICAL for MD5, LOW for Argon2). Supports plain text dumps and SQL dumps (parses INSERT/UPDATE statements to extract password fields).
- Correlation: Synthesizes findings into a unified risk score and traceable report.
- Reports: Generates JSON and Markdown.
- Seeded vulnerable app and dump for validation.
- CI tests on Python; local-only execution (Docker removed).

## Quick Start

```bash
python -m src.analyzer.main \
  --target "http://localhost:5000" \
  --source_dir "vulnerable_app" \
  --dump "seed_data/users_dump.sql" \
  --out_dir "reports" \
  --html
```

Outputs:
- `reports/report.json`
- `reports/report.md`
- `reports/report.html` (styled)

## Project Structure
- `src/analyzer/` core modules (dast, sast, dump_audit, correlate, report, main)
- `vulnerable_app/` Flask app with intentionally vulnerable routes (for testing)
- `seed_data/` sample database dump with varied hash formats
- `tests/` unit tests for analyzers and correlation
- (Docker configuration removed; local-only execution)
- `.github/workflows/ci.yml` CI pipeline

## Run Locally

1) Install vulnerable app deps:
```bash
python -m pip install --upgrade pip
pip install -r vulnerable_app/requirements.txt
```

2) Start the vulnerable app:
```bash
python vulnerable_app/app.py
```
App will run at `http://localhost:5000`. Endpoints: `/search`, `/item`, `/login`.

3) Run the analyzer to generate reports:
```bash
python -m src.analyzer.main --target http://localhost:5000 --source_dir vulnerable_app --dump seed_data/users_dump.sql --out_dir reports --html
```
Reports will be created under `reports/`.

You can pass either a plain text dump (one value per line) or a SQL dump file. For SQL dumps, the analyzer parses `INSERT INTO ... VALUES (...)` and `UPDATE ... SET password=...` statements to extract candidate password/hash values from columns such as `password`, `pass`, `pwd`, `passwd`, `hash`.

## Limitations
- DAST heuristics are generic and may not trigger time-based delays across all RDBMS. Error-based detection is the primary signal in the seeded app.
- SAST rules target common insecure patterns and may require tuning for specific frameworks.
- Correlation relies on parameter and route heuristics; advanced tracing is future work.

## License
MIT
