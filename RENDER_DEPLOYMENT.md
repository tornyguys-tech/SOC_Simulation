# TornSpy / ThreatLens SOC Simulation — Render Deployment Guide

## 1. Prerequisites

- A Render account (https://render.com)
- This repository pushed to GitHub: `https://github.com/tornyguys-tech/SOC_Simulation`
- Python 3.11+ (Render default)

---

## 2. Create PostgreSQL Database

1. In the Render dashboard, click **New → PostgreSQL**.
2. Give it a name: `soc-simulation-db`.
3. Choose the **Free** plan for the class demo.
4. Click **Create Database**.
5. Copy the **Internal Database URL** — you will use it in step 4.

---

## 3. Create the Web Service

1. In the Render dashboard, click **New → Web Service**.
2. Connect your GitHub repository: `tornyguys-tech/SOC_Simulation`.
3. Choose branch: `master`.
4. Set the following:

| Field | Value |
|---|---|
| **Runtime** | Python |
| **Build Command** | `./build.sh` |
| **Start Command** | `gunicorn tornspy.wsgi:application --bind 0.0.0.0:$PORT` |
| **Health Check Path** | `/health/` |

---

## 4. Environment Variables

Set these in the Render dashboard under **Environment** for your web service.

| Variable | Value | Notes |
|---|---|---|
| `SECRET_KEY` | *(generate — see below)* | **Required. Never commit this.** |
| `DEBUG` | `False` | Must be `False` in production |
| `ALLOWED_HOSTS` | `YOUR-SERVICE.onrender.com` | Your actual Render hostname |
| `CSRF_TRUSTED_ORIGINS` | `https://YOUR-SERVICE.onrender.com` | Full HTTPS origin |
| `DATABASE_URL` | *(from Render PostgreSQL — Internal URL)* | Link via "Add from database" |
| `SECURITY_MONITORING_ENABLED` | `True` | Enables ThreatLens SOC pipeline |
| `TRUSTED_PROXY_COUNT` | `1` | Render uses one proxy hop |

### Generating a SECRET_KEY

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

Copy the output and paste it as the `SECRET_KEY` value in Render. Do not share it.

---

## 5. Linking the Database

In the web service's **Environment** tab:

- Click **Add Environment Variable**.
- Under **Add from database**, select `soc-simulation-db`.
- This automatically sets `DATABASE_URL` to the internal PostgreSQL URL.

---

## 6. Build Command

The `build.sh` script runs automatically on every deploy:

```bash
pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
```

No manual migration is required after a deploy.

---

## 7. First Deployment

1. Push the repository to GitHub.
2. Trigger a manual deploy in Render (or it happens automatically on push).
3. Watch the build log — it should end with:
   ```
   Migrations applied successfully.
   Starting Gunicorn...
   ```
4. Once running, open: `https://YOUR-SERVICE.onrender.com/health/`
   — should return `{"status": "ok"}`.

---

## 8. Migrations

Migrations run automatically via `build.sh` on every deploy.

To check migration status locally:

```bash
python manage.py showmigrations
python manage.py migrate --plan
```

All migrations in `tracker/migrations/` and `security_monitoring/migrations/` must be committed to Git.

---

## 9. Creating a Superuser (Admin)

Render does not provide an interactive shell by default on the free plan.

Option A — Render Shell (paid plan):

```bash
python manage.py createsuperuser
```

Option B — Use the existing TornSpy login flow.
The first user to log in with a valid Torn API key is automatically promoted to admin if they are the first SpyUser created.

---

## 10. Static Files

Static files are served via **WhiteNoise** (included in requirements).

`collectstatic` runs automatically in `build.sh`. No separate CDN is required for the class demo.

---

## 11. Client IP Behavior

The application resolves the real client IP using `security_monitoring/utils.py`.

- `TRUSTED_PROXY_COUNT=1` (default) tells the resolver to strip one proxy hop from `X-Forwarded-For`.
- Render adds the real client IP as the leftmost entry before the proxy hop.
- SecurityEvent and SecurityIncident store the resolved IP.
- The SOC dashboard displays it from the incident record — no template-level resolution.

For local development (no proxy), `TRUSTED_PROXY_COUNT=0` or simply omit `X-Forwarded-For` and `REMOTE_ADDR` is used directly.

---

## 12. SOC Verification

After deployment:

1. Navigate to `https://YOUR-SERVICE.onrender.com/requests/` (log in first).
2. Submit a surveillance request with a suspicious faction ID such as:
   `<script>alert('test')</script>`
3. Open `https://YOUR-SERVICE.onrender.com/soc/` (admin required).
4. Verify an incident appears with:
   - real source IP (your browser's public IP, not `127.0.0.1`)
   - extracted IOCs
   - Sigma rule matched
   - risk score > 0
5. Click **TAKE ACTION** — the malicious surveillance request is deleted.
6. Verify the SOC shows **CONTAINED** and the incident/forensic evidence remains.

---

## 13. Health Check

Render monitors `GET /health/` and expects HTTP 200.

The endpoint returns:

```json
{"status": "ok"}
```

It is unauthenticated, lightweight, and does not expose secrets.

---

## 14. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `DisallowedHost` error | `ALLOWED_HOSTS` missing your domain | Add your `.onrender.com` hostname to `ALLOWED_HOSTS` env var |
| `CSRF verification failed` | `CSRF_TRUSTED_ORIGINS` missing | Add `https://YOUR-SERVICE.onrender.com` to `CSRF_TRUSTED_ORIGINS` |
| Static files missing (404) | `collectstatic` not run | Ensure `build.sh` runs and `STATIC_ROOT` is `staticfiles/` |
| Database connection error | `DATABASE_URL` not set | Link Render PostgreSQL via "Add from database" |
| `127.0.0.1` in SOC source IP | `TRUSTED_PROXY_COUNT` not set | Set `TRUSTED_PROXY_COUNT=1` in env vars |
| `500` on first load | Missing migrations | Check Render build logs for migration errors |

---

## 15. Render Blueprint (Optional)

A `render.yaml` blueprint is included in the repository.

You can use it to auto-configure the service — but you **must still** set `SECRET_KEY` and `DATABASE_URL` (or link them) manually, as they are not stored in the blueprint.

---

## 16. Security Notes

- `DEBUG=False` in production (enforced via env var default).
- HTTPS redirect is enabled when `DEBUG=False`.
- Session and CSRF cookies are marked `Secure` in production.
- HSTS is enabled with a short max-age (60s) initially — increase after confirming HTTPS works.
- `SECRET_KEY` must be rotated if ever exposed.
- Do not commit `.env` files or database URLs.

---

## 17. Enrichment

The ThreatLens enrichment module uses a **local deterministic threat intelligence dataset** — no external API keys are required for the class demo.

If you later connect an external threat intelligence feed, add its API key as an environment variable and handle missing keys gracefully in `security_monitoring/services/enrichment.py`.

---

## 18. Known Limitations

| Item | Status |
|---|---|
| PostgreSQL SSL | Enabled via `ssl_require=True` in `dj-database-url` config |
| Media uploads | Not used — no persistent storage needed |
| Email backend | Not configured — not required for the demo |
| Celery / background tasks | Not used — APScheduler runs in-process |
| Interactive shell on free plan | Not available — use Option B for superuser |
