#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""KubeVirt checks for the independent KubeVirt special agent."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    HostLabel,
    Metric,
    Result,
    Service,
    State,
    check_levels,
    render,
)


def _parse_json_section(string_table: list[list[str]]) -> dict[str, Any]:
    if not string_table:
        return {}
    return json.loads("".join("".join(row) for row in string_table))


def _discover_single(section: Mapping[str, Any]) -> Iterable[Service]:
    if section:
        yield Service()


def _state_from_bool(value: Any, what: str) -> Result:
    if value is True:
        return Result(state=State.OK, summary=f"{what}: yes")
    if value is False:
        return Result(state=State.CRIT, summary=f"{what}: no")
    return Result(state=State.UNKNOWN, summary=f"{what}: unknown")


_LABEL_VALUE = re.compile(r"(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?")


def _host_labels_vm_info(section: Mapping[str, Any]) -> Iterable[HostLabel]:
    for key, value in section.get("labels", {}).items():
        if isinstance(value, Mapping):
            value = value.get("value")
        if value is not None:
            yield HostLabel(f"cmk/kubevirt/label/{key}", str(value))
    for key, value in section.get("annotations", {}).items():
        # Defense in depth for older collectors and externally supplied data.
        if isinstance(value, str) and _LABEL_VALUE.fullmatch(value):
            yield HostLabel(f"cmk/kubevirt/annotation/{key}", value)
    if ns := section.get("namespace"):
        yield HostLabel("cmk/kubevirt/namespace", str(ns))
    yield HostLabel("cmk/kubevirt/object", "virtualmachine")


def _check_vm_info(section: Mapping[str, Any]) -> Iterable[Result]:
    if name := section.get("name"):
        yield Result(state=State.OK, summary=f"VM: {name}")
    if ns := section.get("namespace"):
        yield Result(state=State.OK, notice=f"Namespace: {ns}")
    if rs := section.get("run_strategy"):
        yield Result(state=State.OK, notice=f"Run strategy: {rs}")
    disks = section.get("disks") or []
    volumes = section.get("volumes") or []
    yield Result(state=State.OK, notice=f"Disks: {len(disks)}, volumes: {len(volumes)}")


# KubeVirt printableStatus refers to VM lifecycle, not automatically to health.
# Unknown/new statuses deliberately remain UNKNOWN so upstream changes are visible.
_VM_TRANSIENT = {
    "starting", "provisioning", "migrating", "stopping", "terminating",
    "scheduling", "waitingforvolumebinding", "pending",
}
_VM_FAILED = {
    "error", "failed", "crashloopbackoff", "errimagepull", "imagepullbackoff",
    "failedunschedulable", "unschedulable", "datavolumeerror", "failedpvcnotfound", "pvcnotfound",
}
# Some transient statuses have no active VMI while a new instance is prepared.
_VM_NO_RUNTIME = _VM_TRANSIENT | {"stopped", "paused"}


def _vm_state(section: Mapping[str, Any], params: Mapping[str, Any]) -> tuple[State, str]:
    printable = str(section.get("printable_status") or section.get("phase") or "Unknown")
    normalized = printable.casefold().replace(" ", "")
    strategy = str(section.get("run_strategy") or "")
    desired_running = section.get("desired_running")
    if normalized in _VM_FAILED:
        return State.CRIT, printable
    if normalized == "running":
        return (State.WARN if section.get("ready") is False else State.OK), printable
    if normalized == "stopped":
        intentional = strategy.casefold() in {"halted", "manual"} or desired_running is False
        state_key = "stopped_state" if intentional else "unexpected_stopped_state"
        return State(params.get(state_key, State.OK.value if intentional else State.CRIT.value)), printable
    if normalized == "paused":
        return State(params.get("paused_state", State.WARN.value)), printable
    if normalized in _VM_TRANSIENT:
        return State(params.get("transient_state", State.OK.value)), printable
    return State.UNKNOWN, printable


def _check_vm_status(params: Mapping[str, Any], section: Mapping[str, Any]) -> Iterable[Result]:
    state, printable = _vm_state(section, params)
    yield Result(state=state, summary=f"Status: {printable}")
    if section.get("ready") is not None:
        # A stopped/paused/provisioning VM is naturally not ready. Do not
        # override the lifecycle-based result with a second CRIT result.
        ready_state = State.WARN if printable.casefold() == "running" and section["ready"] is False else State.OK
        yield Result(state=ready_state, notice=f"Ready: {section['ready']}")
    if section.get("created") is not None:
        yield Result(state=State.OK, notice=f"Created: {section['created']}")
    if strategy := section.get("run_strategy"):
        yield Result(state=State.OK, notice=f"Run strategy: {strategy}")
    for cond in section.get("conditions", []):
        ctype = cond.get("type")
        if ctype:
            yield Result(state=State.OK, notice=f"Condition {ctype}: {cond.get('status')}")


def _runtime_not_expected(section: Mapping[str, Any] | None) -> bool:
    if not section:
        return False
    printable = str(section.get("printable_status") or "").casefold().replace(" ", "")
    return printable in _VM_NO_RUNTIME


def _discover_vm_placement(
    section_kubevirt_vm_placement_v1: Mapping[str, Any] | None,
    section_kubevirt_vm_status_v1: Mapping[str, Any] | None,
) -> Iterable[Service]:
    if section_kubevirt_vm_placement_v1 is not None:
        yield Service()


def _check_vm_placement(
    section_kubevirt_vm_placement_v1: Mapping[str, Any] | None,
    section_kubevirt_vm_status_v1: Mapping[str, Any] | None,
) -> Iterable[Result]:
    if section_kubevirt_vm_placement_v1 is None:
        return
    node = section_kubevirt_vm_placement_v1.get("node")
    if node:
        yield Result(state=State.OK, summary=f"Node: {node}")
    elif _runtime_not_expected(section_kubevirt_vm_status_v1):
        yield Result(state=State.OK, summary="No active node expected in current VM lifecycle state")
    else:
        yield Result(state=State.WARN, summary="No node assigned")


def _discover_vm_interfaces(
    section_kubevirt_vm_interfaces_v1: Mapping[str, Any] | None,
    section_kubevirt_vm_status_v1: Mapping[str, Any] | None,
) -> Iterable[Service]:
    if section_kubevirt_vm_interfaces_v1 is not None:
        yield Service()


def _check_vm_interfaces(
    section_kubevirt_vm_interfaces_v1: Mapping[str, Any] | None,
    section_kubevirt_vm_status_v1: Mapping[str, Any] | None,
) -> Iterable[Result]:
    if section_kubevirt_vm_interfaces_v1 is None:
        return
    interfaces = section_kubevirt_vm_interfaces_v1.get("interfaces") or []
    if not interfaces:
        if _runtime_not_expected(section_kubevirt_vm_status_v1):
            yield Result(state=State.OK, summary="No active interfaces expected in current VM lifecycle state")
        else:
            yield Result(state=State.WARN, summary="No runtime interfaces found")
        return
    yield Result(state=State.OK, summary=f"Interfaces: {len(interfaces)}")
    for iface in interfaces:
        name = iface.get("name", "unknown")
        ip = iface.get("ip_address") or iface.get("ipAddress") or "no IP"
        mac = iface.get("mac") or "no MAC"
        yield Result(state=State.OK, notice=f"{name}: {ip}, {mac}")


def _check_vm_resources(section: Mapping[str, Any]) -> Iterable[Result]:
    cpu = section.get("cpu_cores")
    mem = section.get("memory_request")
    summary = []
    if cpu is not None:
        summary.append(f"CPU request: {cpu:g} cores")
    if mem is not None:
        summary.append(f"Memory request: {render.bytes(float(mem))}")
    yield Result(state=State.OK, summary=", ".join(summary) if summary else "No explicit CPU/memory request")


def _check_vm_cpu(params: Mapping[str, Any], section: Mapping[str, Any]) -> Iterable[Result]:
    usage = float(section.get("usage", 0.0))
    yield from check_levels(usage, levels_upper=params.get("levels_upper"), metric_name="kubevirt_vm_cpu_usage", label="CPU usage", render_func=lambda v: f"{v:.3f} cores")


def _check_vm_memory(params: Mapping[str, Any], section: Mapping[str, Any]) -> Iterable[Result]:
    value = float(section.get("resident_bytes", 0.0))
    yield from check_levels(value, levels_upper=params.get("levels_upper"), metric_name="kubevirt_vm_memory_resident", label="Resident memory", render_func=render.bytes)


def _discover_items_from_list(key: str):
    def discover(section: Mapping[str, Any]) -> Iterable[Service]:
        for item in section.get(key, []) or []:
            name = item.get("interface") or item.get("drive") or item.get("name")
            if name:
                yield Service(item=str(name))
    return discover


def _check_vm_network(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    for iface in section.get("interfaces", []) or []:
        if iface.get("interface") == item:
            rx = float(iface.get("receive_bytes_per_second", 0.0))
            tx = float(iface.get("transmit_bytes_per_second", 0.0))
            yield Result(state=State.OK, summary=f"RX: {render.networkbandwidth(rx)}, TX: {render.networkbandwidth(tx)}")
            yield Metric("kubevirt_vm_net_rx", rx)
            yield Metric("kubevirt_vm_net_tx", tx)
            return
    yield Result(state=State.UNKNOWN, summary="Interface disappeared")


def _check_vm_disk(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    for drive in section.get("drives", []) or []:
        if drive.get("drive") == item:
            read = float(drive.get("read_bytes_per_second", 0.0))
            write = float(drive.get("write_bytes_per_second", 0.0))
            yield Result(state=State.OK, summary=f"Read: {render.disksize(read)}/s, write: {render.disksize(write)}/s")
            yield Metric("kubevirt_vm_disk_read", read)
            yield Metric("kubevirt_vm_disk_write", write)
            return
    yield Result(state=State.UNKNOWN, summary="Drive disappeared")


def _check_version(section: Mapping[str, Any]) -> Iterable[Result]:
    labels = section.get("labels", {}) or {}
    version = labels.get("kubeversion") or labels.get("version") or "unknown"
    yield Result(state=State.OK, summary=f"KubeVirt version: {version}")


def _check_component_health(section: Mapping[str, Any]) -> Iterable[Result]:
    targets = section.get("targets", []) or []
    down = [t for t in targets if float(t.get("up", 0.0)) != 1.0]
    if down:
        yield Result(state=State.CRIT, summary=f"Down targets: {len(down)}/{len(targets)}")
    else:
        yield Result(state=State.OK, summary=f"All targets up: {len(targets)}")
    for t in targets:
        yield Result(state=State.OK if float(t.get("up", 0.0)) == 1.0 else State.CRIT, notice=f"{t.get('component', 'component')} {t.get('pod', '')}: up={t.get('up')}")


def _check_controller_status(section: Mapping[str, Any]) -> Iterable[Result]:
    fields = ["controller_leading", "controller_ready", "operator_leading", "operator_ready"]
    bad = [f for f in fields if section.get(f) not in (1, 1.0, None)]
    if bad:
        yield Result(state=State.CRIT, summary="Problem: " + ", ".join(bad))
    else:
        yield Result(state=State.OK, summary="Controller/operator status OK")


def _check_workqueues(section: Mapping[str, Any]) -> Iterable[Result]:
    queues = section.get("queues", []) or []
    total_depth = sum(float(q.get("depth", 0.0)) for q in queues)
    total_retries = sum(float(q.get("retries_per_second", 0.0)) for q in queues)
    yield Result(state=State.OK, summary=f"Queues: {len(queues)}, depth: {total_depth:g}, retries/s: {total_retries:.3f}")
    yield Metric("kubevirt_workqueue_depth", total_depth)
    yield Metric("kubevirt_workqueue_retries", total_retries)


def _check_migrations(section: Mapping[str, Any]) -> Iterable[Result]:
    running = float(section.get("running", 0.0))
    pending = float(section.get("pending", 0.0))
    scheduling = float(section.get("scheduling", 0.0))
    yield Result(state=State.OK, summary=f"Running: {running:g}, pending: {pending:g}, scheduling: {scheduling:g}")
    yield Metric("kubevirt_migrations_running", running)
    yield Metric("kubevirt_migrations_pending", pending)


def _check_phase_count(section: Mapping[str, Any]) -> Iterable[Result]:
    phases = section.get("phases", {}) or {}
    if not phases:
        yield Result(state=State.OK, summary="No VMI phase metrics")
        return
    yield Result(state=State.OK, summary=", ".join(f"{k}: {v:g}" for k, v in phases.items()))


def _check_lifecycle(section: Mapping[str, Any]) -> Iterable[Result]:
    timestamps = section.get("timestamps", []) or []
    running = [t for t in timestamps if t.get("status") == "running" and float(t.get("timestamp", 0)) > 0]
    yield Result(state=State.OK, summary=f"Running VMs with lifecycle timestamp: {len(running)}")


def _check_prometheus_connection(section: Mapping[str, Any]) -> Iterable[Result]:
    if section.get("ok") is True:
        yield Result(state=State.OK, summary="Prometheus queries completed successfully")
    elif section.get("ok") is False:
        yield Result(state=State.CRIT, summary=str(section.get("message") or "Prometheus collection failed"))
    else:
        yield Result(state=State.UNKNOWN, summary="Invalid Prometheus connection status")


# API sections
agent_section_kubevirt_vm_info = AgentSection(name="kubevirt_vm_info_v1", parse_function=_parse_json_section, host_label_function=_host_labels_vm_info)
check_plugin_kubevirt_vm_info = CheckPlugin(name="kubevirt_vm_info", service_name="VM info", sections=["kubevirt_vm_info_v1"], discovery_function=_discover_single, check_function=_check_vm_info)

agent_section_kubevirt_vm_status = AgentSection(name="kubevirt_vm_status_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_status = CheckPlugin(name="kubevirt_vm_status", service_name="VM status", sections=["kubevirt_vm_status_v1"], discovery_function=_discover_single, check_function=_check_vm_status, check_default_parameters={}, check_ruleset_name="kubevirt_vm_status")

agent_section_kubevirt_vm_placement = AgentSection(name="kubevirt_vm_placement_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_placement = CheckPlugin(name="kubevirt_vm_placement", service_name="VM placement", sections=["kubevirt_vm_placement_v1", "kubevirt_vm_status_v1"], discovery_function=_discover_vm_placement, check_function=_check_vm_placement)

agent_section_kubevirt_vm_interfaces = AgentSection(name="kubevirt_vm_interfaces_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_interfaces = CheckPlugin(name="kubevirt_vm_interfaces", service_name="VM interfaces", sections=["kubevirt_vm_interfaces_v1", "kubevirt_vm_status_v1"], discovery_function=_discover_vm_interfaces, check_function=_check_vm_interfaces)

agent_section_kubevirt_vm_resources = AgentSection(name="kubevirt_vm_resources_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_resources = CheckPlugin(name="kubevirt_vm_resources", service_name="VM resources", sections=["kubevirt_vm_resources_v1"], discovery_function=_discover_single, check_function=_check_vm_resources)

# Prometheus VM sections
agent_section_kubevirt_vm_cpu = AgentSection(name="kubevirt_vm_cpu_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_cpu = CheckPlugin(name="kubevirt_vm_cpu", service_name="VM CPU", sections=["kubevirt_vm_cpu_v1"], discovery_function=_discover_single, check_function=_check_vm_cpu, check_default_parameters={}, check_ruleset_name="kubevirt_vm_cpu")

agent_section_kubevirt_vm_memory = AgentSection(name="kubevirt_vm_memory_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_memory = CheckPlugin(name="kubevirt_vm_memory", service_name="VM memory", sections=["kubevirt_vm_memory_v1"], discovery_function=_discover_single, check_function=_check_vm_memory, check_default_parameters={}, check_ruleset_name="kubevirt_vm_memory")

agent_section_kubevirt_vm_network = AgentSection(name="kubevirt_vm_network_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_network = CheckPlugin(name="kubevirt_vm_network", service_name="VM network %s", sections=["kubevirt_vm_network_v1"], discovery_function=_discover_items_from_list("interfaces"), check_function=_check_vm_network)

agent_section_kubevirt_vm_disk = AgentSection(name="kubevirt_vm_disk_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_disk = CheckPlugin(name="kubevirt_vm_disk", service_name="VM disk %s", sections=["kubevirt_vm_disk_v1"], discovery_function=_discover_items_from_list("drives"), check_function=_check_vm_disk)

# Platform sections
agent_section_kubevirt_version = AgentSection(name="kubevirt_version_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_version = CheckPlugin(name="kubevirt_version", service_name="KubeVirt version", sections=["kubevirt_version_v1"], discovery_function=_discover_single, check_function=_check_version)

agent_section_kubevirt_component_health = AgentSection(name="kubevirt_component_health_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_component_health = CheckPlugin(name="kubevirt_component_health", service_name="KubeVirt component health", sections=["kubevirt_component_health_v1"], discovery_function=_discover_single, check_function=_check_component_health)

agent_section_kubevirt_controller_status = AgentSection(name="kubevirt_controller_status_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_controller_status = CheckPlugin(name="kubevirt_controller_status", service_name="KubeVirt controller status", sections=["kubevirt_controller_status_v1"], discovery_function=_discover_single, check_function=_check_controller_status)

agent_section_kubevirt_workqueues = AgentSection(name="kubevirt_workqueues_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_workqueues = CheckPlugin(name="kubevirt_workqueues", service_name="KubeVirt workqueues", sections=["kubevirt_workqueues_v1"], discovery_function=_discover_single, check_function=_check_workqueues)

agent_section_kubevirt_migrations = AgentSection(name="kubevirt_migrations_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_migrations = CheckPlugin(name="kubevirt_migrations", service_name="KubeVirt migrations", sections=["kubevirt_migrations_v1"], discovery_function=_discover_single, check_function=_check_migrations)

agent_section_kubevirt_vmi_phase_count = AgentSection(name="kubevirt_vmi_phase_count_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vmi_phase_count = CheckPlugin(name="kubevirt_vmi_phase_count", service_name="KubeVirt VMI phases", sections=["kubevirt_vmi_phase_count_v1"], discovery_function=_discover_single, check_function=_check_phase_count)

agent_section_kubevirt_vm_lifecycle = AgentSection(name="kubevirt_vm_lifecycle_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_vm_lifecycle = CheckPlugin(name="kubevirt_vm_lifecycle", service_name="KubeVirt VM lifecycle", sections=["kubevirt_vm_lifecycle_v1"], discovery_function=_discover_single, check_function=_check_lifecycle)

# Source-host status: Prometheus failure must be visible even if no metrics arrive.
agent_section_kubevirt_prometheus_connection = AgentSection(name="kubevirt_prometheus_connection_v1", parse_function=_parse_json_section)
check_plugin_kubevirt_prometheus_connection = CheckPlugin(name="kubevirt_prometheus_connection", service_name="KubeVirt Prometheus connection", sections=["kubevirt_prometheus_connection_v1"], discovery_function=_discover_single, check_function=_check_prometheus_connection)
