# Changelog

## 0.1.1

- Separate optional Prometheus bearer authentication from the Kubernetes API credential; do not forward credentials across redirects.
- Import only Kubernetes label-compatible annotation values as host labels.
- Add VM CPU, resident memory, and lifecycle status monitoring rules under service monitoring rules.
- Make VM status, node placement, and runtime interfaces aware of stopped and transient VM lifecycles.
- Add regression coverage for credential isolation, annotation filtering, and VM status behavior.

## 0.1.0

- Initial public release.
