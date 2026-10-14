#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Server-side call for the independent KubeVirt special agent."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from cmk.server_side_calls.v1 import HostConfig, SpecialAgentCommand, SpecialAgentConfig, Secret


def _parse_params(params: object) -> dict[str, Any]:
    if isinstance(params, dict):
        return params
    raise TypeError(params)


def _endpoint_value(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    raise TypeError(value)


def _agent_arguments(params: dict[str, Any], host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    api = _endpoint_value(params["kubernetes_api_server"])
    args: list[str | Secret] = [
        "--cluster", str(params["cluster_name"]),
        "--kubernetes-cluster-hostname", host_config.name,
        "--token-id", params["token"],
        "--api-server-endpoint", str(api["endpoint_v2"]),
    ]
    if api.get("verify_cert"):
        args.append("--verify-cert-api")
    if proxy := api.get("proxy"):
        args.extend(["--api-server-proxy", str(proxy)])
    if timeout := api.get("timeout"):
        if timeout.get("connect") is not None:
            args.extend(["--k8s-api-connect-timeout", str(timeout["connect"])])
        if timeout.get("read") is not None:
            args.extend(["--k8s-api-read-timeout", str(timeout["read"])])

    match params.get("namespaces"):
        case ("namespace_include_patterns", patterns):
            for pattern in patterns:
                args.extend(["--namespace-include-patterns", pattern])
        case ("namespace_exclude_patterns", patterns):
            for pattern in patterns:
                args.extend(["--namespace-exclude-patterns", pattern])

    match params.get("import_annotations"):
        case ("include_annotations_as_host_labels", None):
            args.append("--include-annotations-as-host-labels")
        case ("include_matching_annotations_as_host_labels", pattern):
            args.extend(["--include-matching-annotations-as-host-labels", str(pattern)])

    if prom := params.get("prometheus"):
        prom = _endpoint_value(prom)
        args.extend(["--prometheus-endpoint", str(prom["endpoint_v2"])])
        if prom.get("verify_cert"):
            args.append("--usage-verify-cert")
        if proxy := prom.get("proxy"):
            args.extend(["--usage-proxy", str(proxy)])
        if timeout := prom.get("timeout"):
            if timeout.get("connect") is not None:
                args.extend(["--usage-connect-timeout", str(timeout["connect"])])
            if timeout.get("read") is not None:
                args.extend(["--usage-read-timeout", str(timeout["read"])])

    yield SpecialAgentCommand(command_arguments=args)


special_agent_kubevirt = SpecialAgentConfig(
    name="kubevirt",
    parameter_parser=_parse_params,
    commands_function=_agent_arguments,
)
