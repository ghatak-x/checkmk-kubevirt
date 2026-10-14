# KubeVirt v0.1.2

Patch release improving fault isolation between Kubernetes API and Prometheus monitoring.

- Prometheus failures no longer cause the entire special agent to exit unsuccessfully or prevent Kubernetes API VM discovery, VM status, placement, interfaces and resources from updating.
- New **KubeVirt Prometheus connection** service on the KubeVirt source host is **OK** when all configured Prometheus queries succeed, **CRIT** on 401/403 authentication, connectivity, TLS, redirect, failed query or unsafe bearer-token transport errors.
- The collector does not send bearer credentials to unverified remote Prometheus endpoints. Use verified HTTPS with a trusted CA, or a localhost port forward for lab setups.
- A failed Prometheus collection does not publish fresh CPU, memory, network, disk or platform metrics. Existing services may become stale or show missing data; the new connection service explains why.

**Upgrade reminder from v0.1.0:** Starting with v0.1.1, the Kubernetes API bearer token is **not** forwarded to Prometheus. If using an authenticated metrics endpoint (including OpenShift Thanos Querier), configure the independent **Prometheus bearer token** setting in the special-agent rule. It will not be migrated automatically.

**After installing:** Rediscover services on the KubeVirt source host to add **KubeVirt Prometheus connection**. Checkmk 2.5 required. Validate on a real site before publishing.
