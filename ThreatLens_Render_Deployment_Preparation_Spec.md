# ThreatLens / SOC Simulation — Render Deployment Preparation Specification

## Purpose

Prepare the existing `SOC_Simulation` Django project so it is production-deployable on Render.

Repository:
`https://github.com/tornyguys-tech/SOC_Simulation`

This is an implementation task for an agent working directly on the existing project.

The agent must inspect the current repository first, preserve the existing application behavior, and make only the changes necessary for a reliable Render deployment.

---

# 1. Core Requirements

Prepare the project for:

- Render Web Service deployment
- Render PostgreSQL
- Gunicorn
- WhiteNoise static files
- environment-variable based configuration
- Django production security settings
- database migrations during deployment
- reliable startup
- correct forwarded client-IP handling behind Render's proxy
- production-safe logging
- no hard-coded secrets
- no development-only attack/simulation UI

The existing SOC behavior must remain intact.

Do NOT redesign the application.

Do NOT introduce an attack simulator.

Do NOT add a "Launch Attack" button.

Do NOT add a payload input/testing interface.

The existing real-request detection workflow must remain:

    real HTTP request
        -> request parsing
        -> suspicious-request detection
        -> IOC extraction
        -> normalization
        -> enrichment
        -> risk scoring
        -> Sigma evaluation
        -> SecurityEvent / SecurityIncident
        -> SOC dashboard

---

# 2. First: Inspect the Existing Project

Before editing anything:

1. Inspect the repository tree.
2. Inspect:
   - `manage.py`
   - `requirements.txt`
   - `tornspy/settings.py`
   - `tornspy/urls.py`
   - `tornspy/wsgi.py`
   - `security_monitoring/`
   - `tracker/`
   - existing migrations
   - static-file configuration
   - templates
   - middleware
   - database configuration
3. Identify whether SQLite is currently used.
4. Identify whether WhiteNoise is already installed/configured.
5. Identify whether Gunicorn is already present.
6. Identify whether environment variables are already used.
7. Identify all existing security-monitoring settings.
8. Inspect the current client-IP implementation.
9. Inspect all code that creates, links, deletes, or contains:
   - `SecurityEvent`
   - `SecurityIncident`
   - `SecurityLabPayload`
   - `SurveillanceRequest`

Do not assume the current local ZIP or previous implementation is authoritative. The current repository is the source of truth.

---

# 3. Preserve Existing Architecture

Do not replace the ThreatLens pipeline.

Do not rewrite the detector, parser, enrichment, scoring, Sigma, or SOC UI unless required for deployment compatibility.

The production deployment must continue to support:

- automatic detection from real requests
- incident creation
- IOC extraction
- enrichment
- risk scoring
- Sigma rule matching
- incident timeline/evidence
- SOC dashboard
- manual `TAKE ACTION`
- deletion of the exact malicious application record
- retention of forensic incident evidence

The application must continue to treat submitted payloads as data.

Never execute arbitrary submitted JavaScript.

---

# 4. Dependencies

Inspect the existing `requirements.txt` and add only required production dependencies.

The project should have compatible packages for:

- Django
- Gunicorn
- WhiteNoise
- `dj-database-url`
- PostgreSQL driver (`psycopg2-binary` or another compatible PostgreSQL driver already used by the project)
- all existing application dependencies

Do not blindly upgrade every dependency.

Do not introduce incompatible major-version upgrades just for deployment.

The final requirements file must be reproducible and compatible with the project's current Django version.

---

# 5. Production Settings

Update `tornspy/settings.py` for Render.

## SECRET_KEY

Never hard-code a production secret.

Use:

    SECRET_KEY = os.environ.get("SECRET_KEY")

Fail clearly if a required production secret is missing.

Do not print the secret.

---

## DEBUG

Production must default to false.

Use an environment variable such as:

    DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")

Do not allow production deployment to accidentally start with `DEBUG=True`.

---

## ALLOWED_HOSTS

Configure from an environment variable.

Example:

    ALLOWED_HOSTS = [
        host.strip()
        for host in os.environ.get("ALLOWED_HOSTS", "").split(",")
        if host.strip()
    ]

The Render service hostname must be supported through the environment.

Do not use:

    ALLOWED_HOSTS = ["*"]

unless there is a documented, unavoidable reason.

---

# 6. Database

Production must use Render PostgreSQL through `DATABASE_URL`.

Use `dj-database-url` or the project's existing database abstraction.

Expected behavior:

- local development may continue using SQLite if desired
- production uses PostgreSQL when `DATABASE_URL` exists
- connection pooling / persistent connections should be configured sensibly
- migrations must work cleanly against PostgreSQL

Example pattern:

    if os.environ.get("DATABASE_URL"):
        DATABASES = {
            "default": dj_database_url.config(
                default=os.environ["DATABASE_URL"],
                conn_max_age=600,
            )
        }

Do not delete existing local development support unnecessarily.

Do not commit a production database URL.

---

# 7. Static Files

Configure WhiteNoise correctly.

Ensure:

- `django.middleware.security.SecurityMiddleware` remains present
- `whitenoise.middleware.WhiteNoiseMiddleware` is placed immediately after SecurityMiddleware
- `STATIC_URL` is configured
- `STATIC_ROOT` is configured
- production static storage is configured using WhiteNoise's compressed/manifest storage where compatible

Example:

    STATIC_URL = "/static/"
    STATIC_ROOT = BASE_DIR / "staticfiles"

Use the appropriate `STORAGES` configuration for the installed Django version.

Do not rely on Django's development static server in production.

---

# 8. Build Script

Create a root-level:

    build.sh

It should:

1. fail on errors
2. install requirements if Render's build environment requires it
3. run `collectstatic`
4. run migrations

Recommended structure:

    #!/usr/bin/env bash
    set -o errexit

    pip install -r requirements.txt
    python manage.py collectstatic --noinput
    python manage.py migrate

Make the script executable if Git preserves executable permissions.

Do not put secrets into the script.

---

# 9. Render Start Command

The application must run using Gunicorn.

Expected start command:

    gunicorn tornspy.wsgi:application

Verify that:

    tornspy/wsgi.py

exists and imports the correct Django settings module.

Do not use:

    python manage.py runserver

as the production start command.

---

# 10. Render-Compatible Port Handling

Gunicorn should listen on the port expected by Render.

Use a robust configuration such as:

    gunicorn tornspy.wsgi:application --bind 0.0.0.0:$PORT

If the project already has a Render-compatible Gunicorn configuration, preserve it.

Do not hard-code only port 8000 for production.

---

# 11. Health Check

Inspect whether the project already has a health endpoint.

If one exists, make sure it is production-safe and does not require authentication.

If there is no suitable endpoint, add a minimal endpoint such as:

    /health/

Requirements:

- returns HTTP 200 when the Django application is running
- does not expose secrets
- does not dump database contents
- does not perform expensive enrichment
- should be safe for Render health checks

If a database health check is added, keep it lightweight.

Do not create unnecessary public diagnostic information.

---

# 12. Client IP Handling Behind Render

This is critical.

The SOC dashboard currently may show:

    127.0.0.1

or a proxy address locally/behind the hosting infrastructure.

Render traffic passes through proxies/load balancers, so production client-IP resolution must account for forwarded headers.

Implement a centralized helper for client-IP resolution.

Expected logic:

1. inspect the trusted forwarded-client header used by Render, primarily:
   - `X-Forwarded-For`
2. take the first valid public/client address according to the trusted-proxy model
3. fall back to `REMOTE_ADDR`
4. validate the result using Python's `ipaddress` module
5. never crash if a malformed header is supplied

Do not blindly trust arbitrary client-supplied forwarding headers in an environment where an untrusted client can reach the application directly.

Prefer a configurable trusted-proxy boundary.

For example, introduce a setting such as:

    TRUST_PROXY_HEADERS = ...

or another appropriately named production configuration.

Document the trust model in comments.

The helper should be used consistently by the security-monitoring pipeline so:

- SecurityEvent source IP
- SecurityIncident source IP
- SOC dashboard source IP
- logs

all use the same resolved client IP.

Do not duplicate IP-resolution logic in multiple files.

---

# 13. Forwarded Headers

Make Django aware of HTTPS when operating behind Render's reverse proxy.

Use the appropriate Django configuration for the deployment, for example:

    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

Only enable this when appropriate for the Render deployment.

Do not create an insecure configuration where arbitrary external clients can spoof the header while bypassing the trusted proxy.

---

# 14. Production Security

When `DEBUG=False`, configure appropriate Django security settings.

At minimum evaluate:

- `SECURE_SSL_REDIRECT`
- `SESSION_COOKIE_SECURE`
- `CSRF_COOKIE_SECURE`
- `SECURE_PROXY_SSL_HEADER`
- HSTS settings where appropriate
- secure referrer policy where appropriate

Do not blindly enable aggressive HSTS for a custom domain unless HTTPS is definitely working.

Avoid breaking local development.

Use environment variables where a security setting needs deployment-specific control.

---

# 15. CSRF and Render Domain

Make sure Django accepts the Render HTTPS origin.

Configure `CSRF_TRUSTED_ORIGINS` using environment variables.

Example:

    CSRF_TRUSTED_ORIGINS = [
        origin.strip()
        for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
        if origin.strip()
    ]

Values should be complete origins, for example:

    https://your-service.onrender.com

Do not use `*`.

Ensure the existing login/forms/application workflows continue to work.

---

# 16. Database Migrations

Review every migration in:

- `tracker/migrations/`
- `security_monitoring/migrations/`
- other installed apps

Make sure migrations are committed to Git.

Run:

    python manage.py makemigrations --check

and:

    python manage.py migrate --plan

where the local environment permits.

Do NOT automatically generate new migrations unless model/schema changes are actually required.

Do not delete historical migrations.

Do not squash migrations unless explicitly requested.

---

# 17. Existing Security Data Model

Do not remove or rename security models merely to simplify deployment.

Preserve:

- SecurityEvent
- SecurityIncident
- IOC-related models
- Sigma-related persistence
- timeline/evidence
- SurveillanceRequest relationships

If `SecurityLabPayload` is still present for backward compatibility, do not remove it unless the existing application and migrations are safely migrated away from it.

The production deployment must not expose any "lab" or simulator concept in the user-facing UI.

---

# 18. TAKE ACTION Integrity

Do not modify the containment behavior except where needed for deployment.

The required behavior remains:

    incident
       |
       +--> exact linked SurveillanceRequest
                   |
                   v
             TAKE ACTION
                   |
                   v
       delete ONLY that exact request
                   |
                   +--> visible harmless effect disappears
                   |
                   +--> SecurityIncident remains
                   +--> SecurityEvent remains
                   +--> forensic evidence remains

Do not:

- bulk-delete unrelated requests
- search and delete every row containing a similar payload
- delete forensic evidence
- delete unrelated application records

The incident must remain available for the SOC demonstration after containment.

---

# 19. Logging

Configure production-safe logging.

Requirements:

- logs should be visible in Render
- useful application/security events should be logged
- do not log passwords
- do not log session cookies
- do not log authentication tokens
- do not log Django SECRET_KEY
- do not log complete sensitive request headers unnecessarily

Security events should retain enough evidence in the database for the SOC dashboard without leaking secrets into platform logs.

Use standard Python/Django logging.

Do not add noisy debug logging to every request in production.

---

# 20. Environment Variables

Document all required Render environment variables.

At minimum evaluate:

    SECRET_KEY
    DEBUG
    ALLOWED_HOSTS
    DATABASE_URL
    CSRF_TRUSTED_ORIGINS
    SECURITY_MONITORING_ENABLED

Also document any existing API keys required by enrichment services.

Never commit:

- API keys
- database URLs
- passwords
- tokens
- production secrets

Provide safe example values only.

---

# 21. Environment Variable Compatibility

If the existing project already supports variables such as:

    SECURITY_LAB_ENABLED

do not silently break existing local environments.

If that setting is being renamed because the project no longer uses "lab" terminology, support backward compatibility where practical.

Production-facing configuration should use clear naming such as:

    SECURITY_MONITORING_ENABLED

Avoid confusing deployment settings with attack simulation settings.

---

# 22. Render Blueprint

If useful, create:

    render.yaml

Use it only if it improves reproducibility.

A suitable blueprint may define:

- Python web service
- PostgreSQL database
- build command
- start command
- environment variables

However:

- do not hard-code secrets
- do not accidentally overwrite an existing manually managed Render configuration
- do not make destructive assumptions about service names
- document what must still be configured manually

If creating a blueprint, clearly separate generated values from secret values.

---

# 23. No Development Artifacts in Production

Before finalizing:

Search for and review:

- `runserver`
- debug-only routes
- simulator routes
- attack-launch routes
- hard-coded localhost URLs
- hard-coded `127.0.0.1`
- test payloads exposed in UI
- development credentials
- API keys
- passwords
- `.env` files
- debug print statements

Do not delete useful tests merely because they mention malicious payload strings.

The requirement is to prevent accidental exposure of simulation/testing functionality, not to remove security test coverage.

---

# 24. `.gitignore`

Ensure `.gitignore` includes at least:

    __pycache__/
    *.py[cod]
    *.sqlite3
    .env
    .venv/
    venv/
    staticfiles/
    media/
    .pytest_cache/
    .DS_Store

Do not ignore migration files.

Do not ignore source code required for deployment.

---

# 25. Django Deployment Checks

Run, where dependencies are available:

    python manage.py check --deploy

Also run:

    python manage.py check

Then:

    python manage.py makemigrations --check

Then:

    python manage.py collectstatic --noinput

Then test the application.

If PostgreSQL is available in the environment, run migrations against PostgreSQL.

---

# 26. Automated Tests to Add or Update

Add focused tests for deployment-sensitive behavior.

At minimum:

## Client IP tests

Test:

1. direct `REMOTE_ADDR`
2. valid `X-Forwarded-For`
3. multiple forwarded IPs
4. malformed forwarded header
5. IPv4
6. IPv6
7. fallback behavior

Do not make the tests depend on a real external Render request.

## Health endpoint

Verify:

    GET /health/

returns 200.

## Security pipeline

Verify an ordinary request does not create an incident.

Verify the existing suspicious request path still creates:

- SecurityEvent
- SecurityIncident
- extracted payload/evidence
- IOC data where applicable
- Sigma result where applicable

## Containment

Verify `TAKE ACTION` deletes only the linked SurveillanceRequest and preserves the incident/event evidence.

---

# 27. Render Deployment Documentation

Create:

    RENDER_DEPLOYMENT.md

It must contain a concise but complete deployment guide.

Include:

1. prerequisites
2. GitHub branch
3. Render PostgreSQL creation
4. Render Web Service creation
5. build command
6. start command
7. environment variables
8. database configuration
9. health check
10. first deployment
11. migrations
12. superuser creation
13. static files
14. client-IP behavior
15. SOC verification
16. troubleshooting

Do not put real secrets in the document.

Use placeholders such as:

    https://YOUR-SERVICE.onrender.com

---

# 28. Recommended Render Configuration

The final documentation should tell the user to configure the web service approximately as:

    Service Type:
    Web Service

    Runtime:
    Python

    Branch:
    main

    Build Command:
    ./build.sh

    Start Command:
    gunicorn tornspy.wsgi:application --bind 0.0.0.0:$PORT

    Health Check:
    /health/

Use the actual project structure if it differs.

---

# 29. PostgreSQL Configuration

The Render database should be connected to the web service using the internal PostgreSQL connection URL.

The application must read:

    DATABASE_URL

from the environment.

Never hard-code:

- hostname
- username
- password
- database name

inside source code.

---

# 30. Static and Media Files

Treat static files and uploaded media separately.

Static files should be served through WhiteNoise.

If the application uses user-uploaded media that must survive deploys, explicitly document that Render's normal ephemeral filesystem is not persistent.

Do not silently claim uploaded media is durable.

If the current project does not require persistent user uploads, do not introduce unnecessary storage infrastructure.

---

# 31. External Enrichment Services

Inspect the existing enrichment implementation.

If it uses external APIs:

- preserve the current behavior
- move credentials to environment variables
- handle missing API keys gracefully
- do not fail the entire web request just because an enrichment provider is unavailable
- do not expose API keys in SOC UI/logs

If enrichment is intentionally local/mock for the class demo, preserve that behavior and document it.

---

# 32. Startup Reliability

The Render deployment must not depend on:

- an interactive shell
- manually running migrations after every deploy
- manually starting Django
- local files not committed to Git
- developer-specific paths
- localhost-only services

A fresh Render instance should be able to:

    clone repository
        -> install dependencies
        -> collect static
        -> migrate
        -> start Gunicorn
        -> serve Django

---

# 33. Do Not Break Local Development

After production changes, local development should still work.

A developer should be able to use something like:

    python manage.py runserver

with local SQLite if desired.

Production PostgreSQL settings must not make the local project unusable when `DATABASE_URL` is absent.

---

# 34. Final Validation Checklist

Before declaring the project Render-ready, verify:

### Repository

- [ ] `requirements.txt` is complete
- [ ] `build.sh` exists
- [ ] `build.sh` is executable if required
- [ ] `render.yaml` created only if useful
- [ ] `RENDER_DEPLOYMENT.md` exists
- [ ] `.gitignore` is safe
- [ ] no secrets are committed

### Django

- [ ] `DEBUG=False` works
- [ ] `SECRET_KEY` comes from environment
- [ ] `ALLOWED_HOSTS` comes from environment
- [ ] `CSRF_TRUSTED_ORIGINS` works
- [ ] PostgreSQL works through `DATABASE_URL`
- [ ] WhiteNoise works
- [ ] `collectstatic` succeeds
- [ ] migrations succeed
- [ ] `check --deploy` passes or documented warnings are understood

### Gunicorn

- [ ] `tornspy.wsgi` imports correctly
- [ ] Gunicorn starts
- [ ] binds to `0.0.0.0:$PORT`

### Render

- [ ] service configuration documented
- [ ] database configuration documented
- [ ] environment variables documented
- [ ] health check documented

### ThreatLens

- [ ] automatic detection remains automatic
- [ ] no simulator UI introduced
- [ ] no attack-launch button
- [ ] no payload-testing field
- [ ] SecurityEvent creation works
- [ ] SecurityIncident creation works
- [ ] IOC extraction works
- [ ] enrichment works
- [ ] risk scoring works
- [ ] Sigma matching works
- [ ] incident evidence persists
- [ ] TAKE ACTION remains manual
- [ ] only the exact malicious SurveillanceRequest is deleted
- [ ] forensic evidence remains

### Client IP

- [ ] centralized resolver exists
- [ ] `X-Forwarded-For` is handled
- [ ] malformed headers do not crash requests
- [ ] local direct requests still work
- [ ] Render proxy behavior is documented
- [ ] SOC source IP uses the centralized resolver

---

# 35. Required Final Agent Output

After implementing the changes, provide:

## A. Changed files

List every modified/created file.

For each file, briefly explain why it changed.

## B. Render configuration

Provide the exact:

- Build Command
- Start Command
- Health Check Path
- required environment variables

## C. Validation

Report the result of:

    python manage.py check
    python manage.py check --deploy
    python manage.py makemigrations --check
    python manage.py collectstatic --noinput

and relevant tests.

Do not claim a command passed if it could not actually be executed.

If dependencies are unavailable, explicitly state that.

## D. Known limitations

List anything that still requires manual configuration on Render.

## E. Deployment guide

Point to:

    RENDER_DEPLOYMENT.md

---

# 36. Important Constraints

1. Do not rewrite the project from scratch.
2. Do not replace the current SOC architecture.
3. Do not remove the real-request detection pipeline.
4. Do not introduce a simulation/attack UI.
5. Do not execute arbitrary submitted payload JavaScript.
6. Do not add credential/token/cookie theft functionality.
7. Do not add attacker callbacks.
8. Do not add destructive behavior.
9. Do not bulk-delete application records.
10. Do not delete forensic incident evidence during containment.
11. Do not commit secrets.
12. Do not use SQLite as the recommended production database.
13. Do not blindly trust spoofable forwarded headers.
14. Do not make unsupported claims about Render behavior.
15. Do not mark deployment-ready until the project has been inspected and the deployment-sensitive checks have been run where possible.

---

# Definition of Done

The project is ready for Render when:

    GitHub repository
          |
          v
    Render Web Service
          |
          +--> Python dependencies install
          +--> collectstatic succeeds
          +--> PostgreSQL migrations succeed
          +--> Gunicorn starts
          +--> /health/ returns 200
          |
          v
    Production Django application
          |
          v
    Real request
          |
          v
    ThreatLens automatic detection
          |
          v
    SecurityEvent
          |
          v
    IOC extraction / normalization / enrichment
          |
          v
    risk scoring + Sigma
          |
          v
    SecurityIncident
          |
          v
    SOC dashboard
          |
          v
    accurate client IP when available
          |
          v
    manual TAKE ACTION
          |
          +--> exact application record removed
          +--> incident retained
          +--> forensic evidence retained

The deployment must be reproducible, secure enough for the class demonstration, and maintain the existing application's intended behavior.
