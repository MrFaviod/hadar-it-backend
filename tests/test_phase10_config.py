"""Optional search configuration keeps credentials and index paths bounded."""

import pytest
from itsm.config import Settings
from pydantic import ValidationError


def test_search_key_is_redacted_from_representations_and_log_inputs():
    settings = Settings(
        _env_file=None,
        meilisearch_url="http://127.0.0.1:18770",
        meilisearch_api_key="phase10-disposable-search-key",
    )
    assert settings.meilisearch_api_key.get_secret_value() == "phase10-disposable-search-key"
    assert "phase10-disposable-search-key" not in repr(settings)
    assert "phase10-disposable-search-key" in settings.sensitive_values()


@pytest.mark.parametrize("name", ["../index", "a/b", "index?x=1", "", "x" * 65])
def test_index_name_cannot_escape_the_configured_index_endpoint(name):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, search_index_name=name)


@pytest.mark.parametrize("timeout", [0, 61])
def test_optional_search_requests_are_time_bounded(timeout):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, meilisearch_http_timeout_seconds=timeout)
