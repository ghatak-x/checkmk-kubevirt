# KubeVirt v0.1.1

Patch release addressing community review feedback:

- Fixed implicit forwarding of the Kubernetes API bearer token to the independently configured Prometheus endpoint. Prometheus authentication is now separate, optional, and requires a verified HTTPS endpoint for remote destinations (loopback allowed for local port forwards). HTTP redirects are rejected.
- Validated VM annotation values against Kubernetes label-value syntax before importing host labels.
- Added configurable service monitoring rules for VM CPU usage (cores), VM resident memory (bytes), and VM lifecycle state.
- Improved lifecycle state classification and removed false placement/interface WARN states for stopped and transitional VMs.
- Added regression tests.

**Upgrade note:** If Prometheus previously relied on the Kubernetes API token being forwarded implicitly, configure a dedicated Prometheus bearer token in the special-agent rule. If Prometheus is publicly readable, no credential is needed. Checkmk 2.5 required.
