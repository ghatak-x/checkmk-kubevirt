# Kubernetes manifests

`kubevirt_rbac.yaml` creates a ServiceAccount and read-only RBAC for the KubeVirt resources read by the special agent.

Apply it with:

```bash
kubectl apply -f docs/kubevirt_rbac.yaml
kubectl -n checkmk-monitoring create token checkmk-kubevirt
```
