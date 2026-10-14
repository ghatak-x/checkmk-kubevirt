# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Prometheus errors are visible services, never fatal to API VM inventory."""

from __future__ import annotations

import argparse
import json
from unittest.mock import Mock

import pytest
import requests

from test_kubevirt_regressions import special_agent, checks  # Reuse isolated Checkmk mocks.


def _arguments(*, endpoint="https://prometheus.example", verify=True) -> argparse.Namespace:
    return argparse.Namespace(
        verbose=0, debug=False, verify_cert_api=True,
        prometheus_endpoint=endpoint, usage_verify_cert=verify,
        usage_proxy="NO_PROXY", usage_connect_timeout=1, usage_read_timeout=1,
    )


def _mock_main(monkeypatch, agent, args, *, token="k8s-secret", prom_token=None):
    globs = agent.main.__globals__
    monkeypatch.setitem(globs, "parse_args", lambda _: args)
    monkeypatch.setitem(globs, "setup_logging", lambda _: None)
    monkeypatch.setitem(globs, "_resolve_token", lambda _: token)
    monkeypatch.setitem(globs, "_resolve_prometheus_token", lambda _: prom_token)
    return globs


def _sections(output: str):
    assert "<<<kubevirt_prometheus_connection_v1:sep(0)>>>\n" in output
    marker = output.split("<<<kubevirt_prometheus_connection_v1:sep(0)>>>\n", 1)[1]
    return json.loads(marker.splitlines()[0])


def test_api_data_survives_unsafe_prometheus_token(monkeypatch, special_agent, capsys):
    args = _arguments(verify=False)
    globs = _mock_main(monkeypatch, special_agent, args, prom_token="very-secret")
    api_calls = []
    monkeypatch.setitem(globs, "collect_api", lambda _args, token: (api_calls.append(token), special_agent._write_pb("vmcluster", {"kubevirt_vm_status_v1": {"printable_status": "Running"}})))
    monkeypatch.setattr(globs["requests"], "Session", Mock(side_effect=AssertionError("should not make unsafe request")))
    assert special_agent.main([]) == 0
    out, err = capsys.readouterr()
    assert api_calls == ["k8s-secret"]
    assert "<<<<vmcluster>>>>" in out
    assert "<<<kubevirt_vm_status_v1:sep(0)>>>" in out
    assert "<<<<>>>>\n<<<kubevirt_prometheus_connection_v1:sep(0)>>>" in out
    health = _sections(out)
    assert health["ok"] is False
    assert "verified HTTPS" in health["message"]
    assert "very-secret" not in out + err
    assert "k8s-secret" not in out + err


@pytest.mark.parametrize("exception,expected", [
    (requests.exceptions.Timeout("https://token-in-url.example"), "timed out"),
    (requests.exceptions.ConnectionError("secret-in-url"), "connection failed"),
    (requests.exceptions.SSLError("secret-in-url"), "certificate validation"),
    (RuntimeError("HTTP redirect refused for monitoring endpoint: https://secret@url"), "redirect refused"),
    (RuntimeError("Prometheus API returned a failed query status"), "failed query"),
])
def test_prometheus_failures_keep_api_running(monkeypatch, special_agent, capsys, exception, expected):
    globs = _mock_main(monkeypatch, special_agent, _arguments())
    api_calls = []
    monkeypatch.setitem(globs, "collect_api", lambda _args, token: api_calls.append(token))
    def failure(_args, _token):
        raise exception
    monkeypatch.setitem(globs, "collect_prometheus", failure)
    assert special_agent.main([]) == 0
    out, err = capsys.readouterr()
    assert api_calls == ["k8s-secret"]
    health = _sections(out)
    assert health["ok"] is False
    assert expected in health["message"]
    assert "secret-in-url" not in out + err
    assert "secret@url" not in out + err
    assert "token-in-url" not in out + err


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_prometheus_http_error_isolated(monkeypatch, special_agent, capsys, status):
    globs = _mock_main(monkeypatch, special_agent, _arguments())
    api_calls = []
    monkeypatch.setitem(globs, "collect_api", lambda _args, _token: api_calls.append(True))
    response = requests.Response()
    response.status_code = status
    exception = requests.HTTPError("contains-secret", response=response)
    def failure(_args, _token):
        raise exception
    monkeypatch.setitem(globs, "collect_prometheus", failure)
    assert special_agent.main([]) == 0
    out, err = capsys.readouterr()
    assert api_calls == [True]
    assert f"HTTP {status}" in _sections(out)["message"]
    assert "contains-secret" not in out + err


def test_invalid_prometheus_secret_does_not_stop_api(monkeypatch, special_agent, capsys):
    globs = _mock_main(monkeypatch, special_agent, _arguments())
    api_calls = []
    monkeypatch.setitem(globs, "collect_api", lambda _args, _token: api_calls.append(True))
    def missing_secret(_args):
        raise ValueError("token-identifier-and-sensitive-url")
    monkeypatch.setitem(globs, "_resolve_prometheus_token", missing_secret)
    monkeypatch.setitem(globs, "collect_prometheus", lambda *_: pytest.fail("should not query"))
    assert special_agent.main([]) == 0
    out, err = capsys.readouterr()
    assert api_calls == [True]
    assert "ValueError" in _sections(out)["message"]
    assert "token-identifier-and-sensitive-url" not in out + err


def test_prometheus_success_emits_ok_service(monkeypatch, special_agent, capsys):
    globs = _mock_main(monkeypatch, special_agent, _arguments())
    api_calls = []
    prom_calls = []
    monkeypatch.setitem(globs, "collect_api", lambda _args, _token: api_calls.append(True))
    monkeypatch.setitem(globs, "collect_prometheus", lambda _args, token: prom_calls.append(token))
    assert special_agent.main([]) == 0
    out, err = capsys.readouterr()
    assert api_calls == [True]
    assert prom_calls == [None]
    assert _sections(out)["ok"] is True
    assert not err


def test_no_prometheus_endpoint_means_no_service_or_secret_resolution(monkeypatch, special_agent, capsys):
    globs = _mock_main(monkeypatch, special_agent, _arguments(endpoint=None))
    api_calls = []
    monkeypatch.setitem(globs, "collect_api", lambda _args, _token: api_calls.append(True))
    monkeypatch.setitem(globs, "_resolve_prometheus_token", lambda _: pytest.fail("unused secret"))
    assert special_agent.main([]) == 0
    out, err = capsys.readouterr()
    assert api_calls == [True]
    assert "prometheus_connection" not in out
    assert not err


def test_api_failure_is_still_fatal(monkeypatch, special_agent, capsys):
    globs = _mock_main(monkeypatch, special_agent, _arguments())
    def api_failure(*_):
        raise requests.exceptions.ConnectionError("Kubernetes API unavailable")
    monkeypatch.setitem(globs, "collect_api", api_failure)
    monkeypatch.setitem(globs, "collect_prometheus", lambda *_: pytest.fail("Prometheus should not run"))
    assert special_agent.main([]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "Kubernetes API unavailable" in err


def test_prometheus_error_status_is_not_success(special_agent):
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"status": "error", "error": "secret from server"}
    session = Mock()
    session.get.return_value = response
    with pytest.raises(RuntimeError, match="failed query status") as exc:
        special_agent.prom_query(session, "https://prom.example", "up")
    assert "secret from server" not in str(exc.value)


@pytest.mark.parametrize("bad_payload", [
    {"status": "success", "data": []},
    {"status": "success", "data": {}},
    {"status": "success", "data": {"result": {"bad": "shape"}}},
])
def test_malformed_query_is_error(special_agent, bad_payload):
    response = Mock()
    response.status_code = 200
    response.json.return_value = bad_payload
    session = Mock()
    session.get.return_value = response
    with pytest.raises(RuntimeError, match="invalid query result"):
        special_agent.prom_query(session, "https://prom.example", "up")


@pytest.mark.parametrize("ok,state", [(True, 0), (False, 2), (None, 3)])
def test_prometheus_health_check_state(checks, ok, state):
    events = list(checks._check_prometheus_connection({"ok": ok, "message": "connection failed"}))
    assert events[0].state.value == state
    assert checks.check_plugin_kubevirt_prometheus_connection.service_name == "KubeVirt Prometheus connection"
    assert checks.agent_section_kubevirt_prometheus_connection.name == "kubevirt_prometheus_connection_v1"
    assert len(list(checks._discover_single({"ok": False, "message": "failed"}))) == 1
