#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Ruleset for the independent KubeVirt special agent."""

from __future__ import annotations

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    InputHint,
    Integer,
    List,
    MatchingScope,
    Password,
    RegularExpression,
    String,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _migrate_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(value)
    return {k.replace("-", "_"): v for k, v in value.items()}


def _timeout_form() -> Dictionary:
    return Dictionary(
        title=Title("TCP timeouts"),
        elements={
            "connect": DictElement(required=False, parameter_form=Integer(title=Title("Connect timeout"), prefill=DefaultValue(10))),
            "read": DictElement(required=False, parameter_form=Integer(title=Title("Read timeout"), prefill=DefaultValue(12))),
        },
    )


def _endpoint_form(title: str, help_text: str, hint: str, *, optional_auth: bool = False) -> Dictionary:
    elements = {
        "endpoint_v2": DictElement(required=True, parameter_form=String(title=Title("Endpoint"), prefill=InputHint(hint), custom_validate=(validators.LengthInRange(min_value=1),), help_text=Help(help_text))),
        "verify_cert": DictElement(required=True, parameter_form=BooleanChoice(title=Title("SSL certificate verification"), label=Label("Verify certificate"), prefill=DefaultValue(True))),
        "proxy": DictElement(required=False, parameter_form=String(title=Title("Proxy"), help_text=Help("Use FROM_ENVIRONMENT, NO_PROXY, or a proxy URL."), prefill=InputHint("FROM_ENVIRONMENT"))),
        "timeout": DictElement(required=False, parameter_form=_timeout_form()),
    }
    if optional_auth:
        elements["token"] = DictElement(
            required=False,
            parameter_form=Password(
                title=Title("Prometheus bearer token (optional)"),
                help_text=Help("Separate Prometheus credential. The Kubernetes API token is never sent to Prometheus automatically. Use HTTPS for remote endpoints."),
                migrate=migrate_to_password,
            ),
        )
    return Dictionary(
        title=Title(title),
        migrate=_migrate_dict,
        elements=elements,
    )


def _migrate_namespaces(value: object) -> tuple[str, object]:
    match value:
        case (str(name), patterns):
            return (name.replace("-", "_"), patterns)
    raise TypeError(value)


def _migrate_annotations(value: object) -> tuple[str, object]:
    match value:
        case "include-annotations-as-host-labels":
            return ("include_annotations_as_host_labels", None)
        case ("include-annotations-as-host-labels", _):
            return ("include_annotations_as_host_labels", None)
        case ("include-matching-annotations-as-host-labels", pattern):
            return ("include_matching_annotations_as_host_labels", pattern)
        case ("include_annotations_as_host_labels", None):
            return value
        case ("include_matching_annotations_as_host_labels", pattern):
            return value
    raise TypeError(value)


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("KubeVirt"),
        migrate=_migrate_dict,
        elements={
            "cluster_name": DictElement(required=True, parameter_form=String(title=Title("Cluster name"), custom_validate=(validators.LengthInRange(min_value=1),), help_text=Help("Used to make VM piggyback host names unique."))),
            "token": DictElement(required=True, parameter_form=Password(title=Title("Bearer token"), custom_validate=(validators.LengthInRange(min_value=1),), migrate=migrate_to_password)),
            "kubernetes_api_server": DictElement(required=True, parameter_form=_endpoint_form("Kubernetes API server", "Endpoint used to query KubeVirt VirtualMachine and VirtualMachineInstance resources.", "https://api.example:6443")),
            "prometheus": DictElement(required=False, parameter_form=_endpoint_form("Prometheus endpoint", "Prometheus base URL used for kubevirt_* metrics. Do not append /api/v1/query.", "https://prometheus.example:9090", optional_auth=True)),
            "namespaces": DictElement(required=False, parameter_form=CascadingSingleChoice(
                title=Title("Namespaces"), migrate=_migrate_namespaces,
                elements=[
                    CascadingSingleChoiceElement(name="namespace_include_patterns", title=Title("Monitor namespaces matching"), parameter_form=List(element_template=RegularExpression(predefined_help_text=MatchingScope.INFIX, custom_validate=(validators.LengthInRange(min_value=1),)), add_element_label=Label("Add pattern"))),
                    CascadingSingleChoiceElement(name="namespace_exclude_patterns", title=Title("Exclude namespaces matching"), parameter_form=List(element_template=RegularExpression(predefined_help_text=MatchingScope.INFIX, custom_validate=(validators.LengthInRange(min_value=1),)), add_element_label=Label("Add pattern"))),
                ],
            )),
            "import_annotations": DictElement(required=False, parameter_form=CascadingSingleChoice(
                title=Title("Import VM annotations as host labels"), migrate=_migrate_annotations,
                elements=[
                    CascadingSingleChoiceElement(name="include_matching_annotations_as_host_labels", title=Title("Only annotations matching key pattern"), parameter_form=RegularExpression(predefined_help_text=MatchingScope.INFIX, prefill=DefaultValue("checkmk-monitoring$"))),
                    CascadingSingleChoiceElement(name="include_annotations_as_host_labels", title=Title("All valid annotations"), parameter_form=FixedValue(value=None)),
                ],
            )),
        },
    )


rule_spec_special_agent_kubevirt = SpecialAgent(
    name="kubevirt",
    title=Title("KubeVirt"),
    topic=Topic.VIRTUALIZATION,
    parameter_form=_parameter_form,
)
