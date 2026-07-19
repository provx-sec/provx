# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Application settings, loaded once from the environment (rule B-FA-05).

One typed settings object, no scattered ``os.getenv``. ``APP_ENV`` is the gate that decides
whether a client ever sees internal error detail (rule PX-ERRORS): it fails closed, so an
unset or unrecognized value is treated as production.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

#: Environments where echoing internal error detail to a client is acceptable.
DEBUG_ENVIRONMENTS = frozenset({"local", "development", "testing", "staging"})


class Settings(BaseSettings):
    """Runtime configuration for the backend."""

    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: str = "production"
    database_url: str = "postgresql+asyncpg://provx:provx@db:5432/provx"
    http_timeout: float = 10.0

    # Org-wide safety lock. Defaults to on: a deployment that forgets to set it gets the
    # safe behaviour, not the permissive one. Enforced in app.services.safety, and covered
    # by the config-drift test so it can never silently stop being read again.
    safe_mode: bool = True

    # Declared because Compose injects them. An injected setting that no field claims is
    # discarded in silence, which is how SAFE_MODE came to look wired while doing nothing.
    # These are reserved for the phases that consume them; the drift test enforces that
    # every injected variable is accounted for here or explicitly excluded.
    secret_key: str = ""
    redis_url: str = ""
    ai_enabled: bool = False

    @property
    def is_debug_env(self) -> bool:
        """Whether internal error detail may be exposed to API clients."""
        return self.app_env.strip().lower() in DEBUG_ENVIRONMENTS

    @property
    def async_database_url(self) -> str:
        """The database URL with an async driver, tolerating a sync DSN in .env.

        A DSN naming a sync driver would otherwise fail deep inside engine creation with a
        missing-module error, which is a confusing way to learn about a typo.
        """
        url = self.database_url
        for sync_prefix, async_prefix in (
            ("postgresql+psycopg://", "postgresql+asyncpg://"),
            ("postgresql+psycopg2://", "postgresql+asyncpg://"),
            ("postgresql://", "postgresql+asyncpg://"),
            ("sqlite://", "sqlite+aiosqlite://"),
        ):
            if url.startswith(sync_prefix):
                return url.replace(sync_prefix, async_prefix, 1)
        return url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, read from the environment on first use."""
    return Settings()
