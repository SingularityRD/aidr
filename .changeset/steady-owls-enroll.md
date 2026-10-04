---
"@singularityrd/aidr-core": patch
---

Managed mode now defaults to the control plane at https://aidr.singularityrd.com (the origin that serves the connector API) instead of the never-provisioned aidr-control.svc host; local mode is unchanged and still contacts nothing. Enrollment calls (device-start, device-poll, enroll) get a longer timeout than per-tool-call hooks, and required central policy accepts opaque policy version labels in addition to integers.
