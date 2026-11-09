"""Separate child startup from worker ownership checks with finite deadlines."""
from worker_start_probe import run_probe


def test_normal_worker_failure_check_completes_and_reaps_child():
    result = run_probe()
    assert result["ok"] and result["phase"] == "complete" and result["reaped"], result
    assert result["phases"][-3:] == ["stop-before", "stop-after", "complete"], result


def test_slow_interpreter_start_does_not_consume_worker_deadline():
    result = run_probe(startup_delay=5.25)
    assert result["ok"] and result["reaped"] and result["seconds"] >= 5.25, result
    assert result["phases"][0] == "python-first" and "import-ready" in result["phases"]


def test_startup_stall_is_failure_and_child_is_reaped():
    result = run_probe(startup_delay=4, startup_timeout=2, worker_timeout=0.5)
    assert not result["ok"] and result["phase"] == "startup_timeout", result
    assert result["reaped"] and "submit-before" not in result["phases"], result
    assert result["last_phase"] == "python-first" and result["seconds"] < 3.5, result
    # The child may reach faulthandler only shortly before the parent's timeout
    # under host load. The phase marker is synchronous; inspect the stack when
    # it was emitted, without requiring that optional timer to win the race.
    assert "PHASE python-first" in result["stderr_tail"], result
    if "Timeout (" in result["stderr_tail"]:
        assert "_child_main" in result["stderr_tail"], result


def test_import_error_is_startup_failure_with_partial_traceback():
    result = run_probe(import_fail=True, startup_timeout=2)
    assert not result["ok"] and result["phase"] == "startup_failed", result
    assert result["reaped"] and result["last_phase"] == "import-before", result
    assert "synthetic import failure" in result["stderr_tail"], result


def test_worker_stall_is_failure_not_a_successful_stop():
    result = run_probe(mode="work_stall", worker_timeout=1)
    assert not result["ok"] and result["phase"] == "worker_timeout", result
    assert result["reaped"] and result["last_phase"] == "submit-before", result
    assert "Timeout (" in result["stderr_tail"] and "fail_start" in result["stderr_tail"], result


def test_worker_assertion_error_is_failure_with_partial_traceback():
    result = run_probe(mode="assert_fail")
    assert not result["ok"] and result["phase"] == "worker_failed", result
    assert result["reaped"] and "synthetic worker assertion failure" in result["stderr_tail"], result


def test_ready_reader_start_failure_still_reaps_real_child():
    from unittest.mock import patch

    with patch("worker_start_probe.threading.Thread.start", side_effect=RuntimeError("no reader")):
        result = run_probe()
    assert not result["ok"] and result["phase"] == "reader_failed", result
    assert result["reaped"] and "no reader" in result["reader_error"], result
