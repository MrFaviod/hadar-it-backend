"""External consumers cannot race an in-process demo reset."""
from itsm.tasks.runtime import WORKER_REFUSED_EXIT_CODE
from tests.conftest import read_worker_log, run_migrations, running_worker, worker_events


def test_resetting_demo_refuses_external_worker(settings_factory, monkeypatch, tmp_path):
    monkeypatch.setenv("RELEASE_MODE", "demo")
    monkeypatch.setenv("ITSM_DEMO_DATA_DIRECTORY", str(tmp_path / "demo"))
    settings = settings_factory(demo_data_directory=tmp_path / "demo")
    assert run_migrations(settings).returncode == 0
    log = tmp_path / "worker.log"
    with running_worker(settings, log) as process:
        code = process.wait(timeout=10)
    assert code == WORKER_REFUSED_EXIT_CODE, read_worker_log(log)
    assert worker_events(log, "worker.refused")
    assert not worker_events(log, "worker.started")
    assert "Executing " not in read_worker_log(log)
