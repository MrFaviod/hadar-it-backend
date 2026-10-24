"""Live Redis-backed queue check.

Skipped unless ``ITSM_TEST_REDIS_URL`` points at an isolated Redis instance you
own (any database you control). The test uses a disposable key prefix through
Huey's queue name only; it does not flush the instance.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import running_worker, wait_for_status

REDIS_URL = os.environ.get("ITSM_TEST_REDIS_URL", "")

pytestmark = pytest.mark.skipif(
    not REDIS_URL,
    reason="ITSM_TEST_REDIS_URL not set (isolated live Redis only)",
)


def test_redis_task_storage_runs_the_echo_task(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    settings_factory: Callable[..., Settings],
    tmp_path: Path,
) -> None:
    settings = settings_factory(task_storage="redis", task_redis_url=REDIS_URL)
    api, auth = signed_in_client(settings)

    submitted = api.post("/api/v1/tasks/demo", json={"message": "redis"}, headers=auth)

    assert submitted.status_code == 202, submitted.text
    task_id = submitted.json()["task_id"]
    with running_worker(settings, log_path=tmp_path / "worker-redis.log"):
        completed = wait_for_status(api, task_id, {"complete"})

    assert completed["result"] == {"message": "redis"}
