# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    DataSize, DefaultValue, DictElement, Dictionary, Float,
    IECMagnitude, LevelDirection, ServiceState, SimpleLevels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic

def _parameter_form():
    return Dictionary(elements={
        "stopped_state": DictElement(required=False, parameter_form=ServiceState(
            title=Title("State for intentionally stopped VMs"),
            prefill=DefaultValue(0),
        )),
        "unexpected_stopped_state": DictElement(required=False, parameter_form=ServiceState(
            title=Title("State for unexpectedly stopped VMs"),
            prefill=DefaultValue(2),
        )),
        "paused_state": DictElement(required=False, parameter_form=ServiceState(
            title=Title("State for paused VMs"),
            prefill=DefaultValue(1),
        )),
        "transient_state": DictElement(required=False, parameter_form=ServiceState(
            title=Title("State for normal transitional VM statuses"),
            help_text=Help("For Starting, Provisioning, Migrating, Stopping, and similar states. No time-based escalation is applied unless status durations become reliably available."),
            prefill=DefaultValue(0),
        )),
    })


rule_spec_kubevirt_vm_status = CheckParameters(
    name="kubevirt_vm_status", title=Title("KubeVirt VM lifecycle status"),
    topic=Topic.VIRTUALIZATION, parameter_form=_parameter_form,
    condition=HostCondition(),
)
