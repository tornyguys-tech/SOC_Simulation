"""
Django settings for tornspy project.
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Core secrets — must come from environment in production
# ---------------------------------------------------------------------------

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    # Insecure default is ONLY used for local development (DEBUG=True).
    # Render must always supply SECRET_KEY via environment variables.
    "django-insecure-%$vxtqd-x9rugtf4g&vv0&km&=9rd53wo)9wqrrfhq1qhup0r%",
)

# ---------------------------------------------------------------------------
# Debug — default False for production safety
# ---------------------------------------------------------------------------

DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Allowed hosts — from environment in production
# ---------------------------------------------------------------------------

ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("ALLOWED_HOSTS", "").split(",")
    if host.strip()
]

# In development (DEBUG=True) add localhost automatically
if DEBUG:
    ALLOWED_HOSTS = list(dict.fromkeys(
        ALLOWED_HOSTS + ["localhost", "127.0.0.1", "testserver"]
    ))


# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    "tracker",
    "security_monitoring",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

# ---------------------------------------------------------------------------
# Security Monitoring
# ---------------------------------------------------------------------------

# Enable on the environment where the SOC demonstration is running.
# Backward-compatible with the old SECURITY_LAB_ENABLED name.
SECURITY_MONITORING_ENABLED = os.environ.get(
    "SECURITY_MONITORING_ENABLED",
    os.environ.get("SECURITY_LAB_ENABLED", "True"),
).lower() in ("1", "true", "yes")

# Trusted reverse-proxy hop count for client-IP resolution (security_monitoring/utils.py).
# 0 = no proxy (pure direct access).
# 1 = one trusted proxy, e.g. Render (default).
# Override via TRUSTED_PROXY_COUNT env var.
TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "1"))


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # WhiteNoise must be immediately after SecurityMiddleware
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "security_monitoring.middleware.ThreatLensInspectionMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "tornspy.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "tornspy.wsgi.application"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

_database_url = os.environ.get("DATABASE_URL")
if _database_url:
    # Use dj-database-url to parse the Render PostgreSQL connection string.
    import dj_database_url
    DATABASES["default"] = dj_database_url.config(
        default=_database_url,
        conn_max_age=600,
        ssl_require=True,
    )


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# ---------------------------------------------------------------------------
# Static files — WhiteNoise
# ---------------------------------------------------------------------------

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# WhiteNoise compressed-manifest storage for production fingerprinting.
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}


# ---------------------------------------------------------------------------
# CSRF — accept Render origin and any configured origins
# ---------------------------------------------------------------------------

CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]


# ---------------------------------------------------------------------------
# Production security settings (only when DEBUG=False)
# ---------------------------------------------------------------------------

if not DEBUG:
    # Tell Django that Render's proxy supplies HTTPS via this header.
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

    # Redirect plain HTTP to HTTPS — only on Render (where DATABASE_URL is set).
    # Disabled locally so tests and local runserver work without SSL.
    SECURE_SSL_REDIRECT = bool(os.environ.get("DATABASE_URL"))

    # Secure session and CSRF cookies.
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # HSTS — short max-age initially; increase after confirming HTTPS works.
    SECURE_HSTS_SECONDS = 60
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False

    # Content-type sniffing prevention.
    SECURE_CONTENT_TYPE_NOSNIFF = True


# ---------------------------------------------------------------------------
# Logging — production-safe, visible in Render log stream
# ---------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
        "security_monitoring": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}


# ---------------------------------------------------------------------------
# Default primary key type
# ---------------------------------------------------------------------------

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
