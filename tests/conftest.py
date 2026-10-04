from __future__ import annotations

import os

import pytest

from privacy_gateway.config import Config, load_config

SKIP_USER_CONFIG_ENV = {"PGW_SKIP_USER_CONFIG": "1"}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "posix_only: nur unter macOS/Linux prüfbar")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if os.name != "nt":
        return
    skip = pytest.mark.skip(reason="POSIX-Rechte, Symlinks bzw. launchd fehlen unter Windows")
    for item in items:
        if "posix_only" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def default_config() -> Config:
    """Bundled defaults only; the user's ~/.config file is ignored."""
    return load_config(env=SKIP_USER_CONFIG_ENV)
