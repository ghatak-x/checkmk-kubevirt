# Changelog

## 0.1.2

- Keep Kubernetes API VM collection running when Prometheus credentials, transport, authentication, queries or connectivity fail.
- Add a source-host **KubeVirt Prometheus connection** service: OK when configured queries succeed, CRIT when metrics collection fails. No service is discovered if Prometheus is not configured.
- Preserve strict protection against sending Prometheus bearer tokens to unverified remote endpoints; show the configuration problem in the connection service instead of aborting the special agent.
- Treat failed and malformed Prometheus query responses as errors rather than successful empty results.
- Security/upgrade reminder: since v0.1.1, Prometheus never receives the Kubernetes API token automatically. Configure a separate Prometheus bearer token for authenticated endpoints (including OpenShift Thanos Querier).

## 0.1.1

- Separate optional Prometheus bearer authentication from the Kubernetes API credential; do not forward credentials across redirects.
- Import only Kubernetes label-compatible annotation values as host labels.
- Add VM CPU, resident memory, and lifecycle status monitoring rules under service monitoring rules.
- Make VM status, node placement, and runtime interfaces aware of stopped and transient VM lifecycles.
- Add regression coverage for credential isolation, annotation filtering, and VM status behavior.

## 0.1.0

- Initial public release.
