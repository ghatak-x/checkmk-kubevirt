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
        "levels_upper": DictElement(required=False, parameter_form=SimpleLevels(
            title=Title("VM resident memory"),
            help_text=Help("Upper thresholds for resident VM memory in bytes. These are absolute values, not percentages of guest allocated memory."),
            form_spec_template=DataSize(displayed_magnitudes=[IECMagnitude.MEBI, IECMagnitude.GIBI, IECMagnitude.TEBI]),
            level_direction=LevelDirection.UPPER,
            prefill_fixed_levels=DefaultValue((2 * 1024**3, 3 * 1024**3)),
        )),
    })


rule_spec_kubevirt_vm_memory = CheckParameters(
    name="kubevirt_vm_memory", title=Title("KubeVirt VM resident memory"),
    topic=Topic.VIRTUALIZATION, parameter_form=_parameter_form,
    condition=HostCondition(),
)
