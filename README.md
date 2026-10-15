# PHANTOM

An AI-assisted cybersecurity analysis workbench for reviewing **website security
configuration**, **source code**, and **security logs** — with explainable,
evidence-backed findings and actionable remediation guidance.

PHANTOM is an educational tool for students and early-career developers. It is
**not** a penetration-testing framework and does not replace a professional
security audit. All checks are passive; findings are advisory.

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 0 — Foundation | FastAPI app, configuration, database, migrations, base UI, CSRF + security headers, test harness | ✅ Done |
| 1 — Website checker | URL validation, SSRF protections, header rules | ✅ Done |
| 2 — Source review | Paste/upload flow, deterministic rules, line references | ✅ Done |
| 3 — Log analysis | Field parsing, repeated-failure rules, sample logs | ✅ Done |
| 4 — AI assistance | Provider adapter, consent gates, redaction, structured outputs | ⬜ Pending |
| 5 — History & reports | Persistence UI, deletion, HTML report export | ⬜ Pending |
| 6 — Polish & release | Accessibility, security review, docs, screenshots | ⬜ Pending |

## Requirements

- Linux (developed on Ubuntu), Python **3.12+**
- No external services required; everything runs locally against SQLite

## Setup

```bash
git clone <your-fork-url> phantom && cd phantom   # skip if already in the repo
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Configuration
cp .env.example .env
.venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))"
#   ^ paste the generated value as SECRET_KEY in .env

# Create the database schema
.venv/bin/alembic upgrade head

# Run
.venv/bin/uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. Interactive API docs (`/docs`) are available in
development only.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | `production` requires `SECRET_KEY` and disables `/docs` |
| `SECRET_KEY` | ephemeral (dev) | Signs CSRF tokens. Set a long random value |
| `DATABASE_URL` | `sqlite:///./phantom.db` | SQLAlchemy URL (PostgreSQL-ready) |
| `MAX_BODY_BYTES` | `1048576` | Hard cap for any request body |
| `UPLOAD_MAX_BYTES` | `524288` | Per-upload cap for code/log workflows |
| `AI_PROVIDER` | *(empty)* | Empty = AI assistance disabled (Phase 4) |

Secrets are read from the environment or a local `.env` (git-ignored). API keys
are never displayed, logged, or stored in analysis records.

## Tests

```bash
.venv/bin/python -m pytest
```

The suite covers input validation, the data model and migrations, CSRF
enforcement, response security headers, body-size limits, and page rendering —
all with isolated temporary databases and no network access.

## Safe-use boundaries

- **Passive checks only.** PHANTOM never executes exploits, attacks
  credentials, scans ports, or crawls sites.
- **Authorization.** Only assess websites you own or have explicit permission
  to test.
- **No guarantees.** Findings may contain false positives and false negatives.
  A clean result is not proof that a system is secure.
- **Privacy.** Code and logs stay on your machine. Once AI assistance lands
  (Phase 4), content is sent to a provider only after explicit consent and
  secret redaction.

## Limitations

- Single-user, local-first application; no accounts or multi-tenancy.
- Website checks observe response headers and redirects only; they cannot see
  server-side configuration.
- Log rules cover common syslog/ISO/Python formats and sshd-style lines; exotic formats
  are scanned for content indicators but may not be structured end-to-end.
- The optional Semgrep integration from the PRD is deferred: useful rule sets are
  fetched from Semgrep's registry at run time, which would break the local-first,
  no-external-calls stance. Local deterministic rules keep reviews fully offline.
- AI explanations are advisory, validated for structure, and never override
  deterministic evidence.

## License

Not yet chosen — decide before publishing to a public repository.
