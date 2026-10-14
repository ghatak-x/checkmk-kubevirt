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
            title=Title("VM CPU usage (CPU cores)"),
            help_text=Help("Upper limits for the observed CPU usage in cores. 1.0 means one full CPU core, not 1 percent."),
            form_spec_template=Float(unit_symbol="cores"),
            level_direction=LevelDirection.UPPER,
            prefill_fixed_levels=DefaultValue((1.5, 1.9)),
        )),
    })


rule_spec_kubevirt_vm_cpu = CheckParameters(
    name="kubevirt_vm_cpu", title=Title("KubeVirt VM CPU usage"),
    topic=Topic.VIRTUALIZATION, parameter_form=_parameter_form,
    condition=HostCondition(),
)
