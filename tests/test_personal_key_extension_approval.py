"""A permission-bound personal key may stage, but not approve deferred owner work."""

import pytest
from itsm.identity.service import IdentityService, PermissionDenied
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.test_native_extensions import MODULE_ID
from tests.test_native_extensions import env as _env

env = _env


def test_personal_key_cannot_approve_or_resume_extension(env):
    with env.factory() as session:
        identity = IdentityService(session, env.settings)
        browser = identity.login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
        key = identity.issue_api_key(
            browser, label="Developer", permissions=["system.modules"], expires_at=None
        )
        actor = identity.authenticate_token(key["token"]).principal
    candidate = env.validated()
    before = env.host.discovery(browser)
    with pytest.raises(PermissionDenied):
        env.host.approve_candidate(
            actor,
            candidate["id"],
            digest=candidate["digest"],
            expected_version=candidate["currentRevision"],
        )
    assert env.host.discovery(browser) == before
    assert env.host.candidate_detail(browser, candidate["id"])["id"] == candidate["id"]
    env.host.approve_candidate(
        browser,
        candidate["id"],
        digest=candidate["digest"],
        expected_version=candidate["currentRevision"],
    )
    installed = env.host.discovery(browser)
    with pytest.raises(PermissionDenied):
        env.host.set_enabled(actor, MODULE_ID, enabled=False, expected_version=1)
    assert env.host.discovery(browser) == installed
