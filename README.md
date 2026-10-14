# checkmk-kubevirt

Checkmk special agent for generic KubeVirt environments.

The integration discovers KubeVirt `VirtualMachine` and `VirtualMachineInstance` resources as Checkmk piggyback hosts and creates VM/platform services from the Kubernetes/KubeVirt API and Prometheus metrics.

## Status

Initial community release. The package has been validated in a lab environment; test it in your own Checkmk site before production rollout.

## Target platforms

- Upstream KubeVirt
- KubeVirt-based virtualization platforms
- OpenShift Virtualization-style environments after separate validation

## Features

- KubeVirt VM and VMI discovery
- Piggyback VM hosts with VM CPU, memory, disk, network, placement, resources and info services
- KubeVirt platform checks for component health, controller status, migrations, VMI phases, VM lifecycle, workqueues and version
- Kubernetes API and Prometheus-based collection without installing an agent inside the guest VMs

## Repository layout

```text
cmk_addons/plugins/kubevirt/   Checkmk add-on source tree
docs/                          Kubernetes RBAC example manifests
tools/build_mkp.py             MKP packaging helper
tests/                         Static packaging and syntax tests
dist/                          Build output, created locally
```

## Installation

Build the MKP locally or download it from a GitHub release / Checkmk Exchange page:

```bash
python tools/build_mkp.py
mkp add dist/kubevirt-0.1.0.mkp
mkp enable kubevirt 0.1.0
cmk -R
```

The package can also be uploaded through the Checkmk GUI under **Setup > Extension packages**.

## Kubernetes RBAC

The special agent needs a Kubernetes bearer token that can read KubeVirt VM resources. A minimal example is provided in:

```text
docs/kubevirt_rbac.yaml
```

Apply it to the monitored cluster and create/use a token for the `checkmk-kubevirt` ServiceAccount:

```bash
kubectl apply -f docs/kubevirt_rbac.yaml
kubectl -n checkmk-monitoring create token checkmk-kubevirt
```

Prometheus access depends on your cluster setup. If Prometheus is protected by Kubernetes authentication, use a token that is allowed to query the selected Prometheus endpoint.

## Configuration

1. Create a host in Checkmk for the KubeVirt cluster/source endpoint.
2. Configure the **KubeVirt** special agent rule with the API endpoint, token, Prometheus endpoint and cluster name.
3. Run service discovery on the source host.
4. Run service discovery on the generated VM piggyback hosts.

## Relationship to checkmk-harvester

This package monitors the generic KubeVirt layer. For Harvester platform, Longhorn and node monitoring, use the separate `checkmk-harvester` package. A Harvester environment can use both packages when VM-level KubeVirt monitoring and Harvester platform monitoring are both required.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest
python tools/build_mkp.py
```

## License

GPL-2.0-only. See `LICENSE`.
