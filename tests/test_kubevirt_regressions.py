# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Isolated regressions that run without a Checkmk site or live KubeVirt cluster."""

from __future__ import annotations

import importlib.util
import runpy
import sys
import types
from enum import IntEnum
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def special_agent(monkeypatch):
    cmk = types.ModuleType("cmk")
    cmk.__path__ = []
    password = types.ModuleType("cmk.password_store")
    password.__path__ = []
    api = types.ModuleType("cmk.password_store.v1_unstable")
    api.parser_add_secret_option = lambda parser, long, help, required: (
        parser.add_argument(long), parser.add_argument(long + "-id")
    )
    api.resolve_secret_option = lambda args, name: types.SimpleNamespace(
        reveal=lambda: getattr(args, name, None) or "secret-from-password-store"
    )
    for name, module in [("cmk", cmk), ("cmk.password_store", password), ("cmk.password_store.v1_unstable", api)]:
        monkeypatch.setitem(sys.modules, name, module)
    path = ROOT / "cmk_addons/plugins/kubevirt/libexec/agent_kubevirt"
    namespace = runpy.run_path(str(path), run_name="agent_test")
    return types.SimpleNamespace(**namespace)


@pytest.fixture
def checks(monkeypatch):
    class State(IntEnum):
        OK = 0
        WARN = 1
        CRIT = 2
        UNKNOWN = 3

    class Result:
        def __init__(self, state, summary=None, notice=None):
            self.state, self.summary, self.notice = state, summary, notice

    class Service:
        def __init__(self, item=None):
            self.item = item

    class HostLabel:
        def __init__(self, name, value):
            self.name, self.value = name, value

    class Metric:
        def __init__(self, name, value, **kwargs):
            self.name, self.value = name, value

    class Plugin:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    agent_base = types.ModuleType("cmk.agent_based")
    agent_base.__path__ = []
    v2 = types.ModuleType("cmk.agent_based.v2")
    for name, item in {"State": State, "Result": Result, "Service": Service, "Metric": Metric,
                       "HostLabel": HostLabel, "AgentSection": Plugin, "CheckPlugin": Plugin}.items():
        setattr(v2, name, item)
    v2.render = types.SimpleNamespace(bytes=lambda n: f"{n} bytes", networkbandwidth=str, disksize=str)
    v2.check_levels = lambda value, **kwargs: iter([Result(State.OK, summary=f"{value}"), Metric(kwargs.get("metric_name"), value)])
    cmk = types.ModuleType("cmk")
    cmk.__path__ = []
    for name, mod in [("cmk", cmk), ("cmk.agent_based", agent_base), ("cmk.agent_based.v2", v2)]:
        monkeypatch.setitem(sys.modules, name, mod)
    path = ROOT / "cmk_addons/plugins/kubevirt/agent_based/kubevirt.py"
    spec = importlib.util.spec_from_file_location("kubevirt_checks_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_reject_large_and_multiline_annotations(special_agent, checks):
    assert special_agent.valid_annotation_value("version_1")
    assert special_agent.valid_annotation_value("")
    assert not special_agent.valid_annotation_value("{\"secret\": \"value\"}")
    assert not special_agent.valid_annotation_value("first\nsecond")
    assert not special_agent.valid_annotation_value("x" * 64)
    vm = {"metadata": {"name": "testvm", "namespace": "default", "annotations": {
        "allowed": "v1", "last-applied": "{\"foo\":true}\n", "long": "z" * 64}}, "spec": {}, "status": {}}
    sections = special_agent._vm_section_data(vm, None, "cluster", "source", True, None)
    assert sections["kubevirt_vm_info_v1"]["annotations"] == {"allowed": "v1"}
    labels = list(checks._host_labels_vm_info({"annotations": {"bad": "x\ny", "valid": "hello"}}))
    assert all(label.name != "cmk/kubevirt/annotation/bad" for label in labels)
    assert any(label.value == "hello" for label in labels)


def test_prometheus_not_given_kubernetes_token(special_agent):
    args = types.SimpleNamespace(prometheus_endpoint="https://prometheus.example", usage_verify_cert=True,
                                 usage_proxy="NO_PROXY", usage_connect_timeout=1, usage_read_timeout=1)
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.get.return_value = types.SimpleNamespace(
        status_code=200, raise_for_status=lambda: None,
        json=lambda: {"status": "success", "data": {"result": []}},
    )
    with patch.object(special_agent.requests, "Session", return_value=session):
        with patch.object(special_agent, "KUBEVIRT_QUERIES", {"cpu": "up", "memory": "up",
                    "net_rx": "up", "net_tx": "up", "disk_read": "up", "disk_write": "up",
                    "version": "up", "component_up": "up", "controller_leading": "up",
                    "controller_ready": "up", "operator_leading": "up", "operator_ready": "up",
                    "workqueue_depth": "up", "workqueue_adds": "up", "workqueue_retries": "up",
                    "workqueue_unfinished": "up", "migrations_pending": "up", "migrations_running": "up",
                    "migrations_scheduling": "up", "migrations_unset": "up", "vmi_phase_count": "up",
                    "vm_running": "up", "vm_starting": "up", "vm_non_running": "up",
                    "vm_migrating": "up", "vm_error": "up"}):
            special_agent.collect_prometheus(args)  # public endpoint: no authentication
    assert "Authorization" not in session.headers.update.call_args_list.__str__()
    assert session.get.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("url,verify,allowed", [
    ("http://evil.example", True, False), ("https://evil.example", False, False),
    ("https://prometheus.example", True, True), ("http://127.0.0.1:9090", False, True),
])
def test_prometheus_token_transport(special_agent, url, verify, allowed):
    if allowed:
        special_agent.validate_prometheus_token_transport(url, verify)
    else:
        with pytest.raises(ValueError):
            special_agent.validate_prometheus_token_transport(url, verify)


def test_reject_redirect(special_agent):
    session = Mock()
    session.get.return_value.status_code = 302
    with pytest.raises(RuntimeError, match="redirect refused"):
        special_agent._get_json(session, "https://prometheus.example/api/v1/query")
    assert session.get.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("status,run_strategy,expected", [
    ("Running", "Always", 0), ("Stopped", "Halted", 0),
    ("Stopped", "Always", 2), ("Starting", "Always", 0),
    ("Provisioning", "Always", 0), ("Migrating", "Always", 0),
    ("Paused", "Always", 1), ("DataVolumeError", "Always", 2),
    ("ErrImagePull", "Always", 2), ("FailedUnschedulable", "Always", 2),
    ("PVCNotFound", "Always", 2), ("NewUpstreamState", "Always", 3),
])
def test_lifecycle_mapping(checks, status, run_strategy, expected):
    state, _ = checks._vm_state({"printable_status": status, "run_strategy": run_strategy}, {})
    assert state.value == expected


def test_stopped_vm_has_normal_placement_and_interfaces(checks):
    stopped = {"printable_status": "Stopped", "run_strategy": "Halted", "ready": False}
    placement = list(checks._check_vm_placement({"node": None}, stopped))
    interfaces = list(checks._check_vm_interfaces({"interfaces": []}, stopped))
    assert placement[0].state == checks.State.OK
    assert interfaces[0].state == checks.State.OK
    assert list(checks._check_vm_placement({"node": None}, {"printable_status": "Running"}))[0].state == checks.State.WARN


def test_status_rules_wired(checks):
    assert checks.check_plugin_kubevirt_vm_status.check_ruleset_name == "kubevirt_vm_status"
    assert checks.check_plugin_kubevirt_vm_memory.check_ruleset_name == "kubevirt_vm_memory"
    assert checks.check_plugin_kubevirt_vm_cpu.check_ruleset_name == "kubevirt_vm_cpu"
    assert list(checks._check_vm_status({}, {"printable_status": "Stopped", "ready": False,
                                          "run_strategy": "Halted"}))[0].state == checks.State.OK
