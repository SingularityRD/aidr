---
"@singularityrd/aidr-cli": patch
---

`aidr doctor` compares the machine clock with the control plane's (its HTTP `Date` header) in managed mode: it warns above 60 seconds of offset and fails above 300 seconds, because signed licences, approvals, enrollment and device sessions are time-checked. An unreachable control plane or a missing `Date` header is reported as "not compared", never as a pass. Local mode makes no network call and shows no clock line.
