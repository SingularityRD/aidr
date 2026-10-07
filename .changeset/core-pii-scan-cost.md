---
"@singularityrd/aidr-core": patch
---

- The DLP email pattern is now matched from each `@` instead of from every word boundary. It reports exactly the same matches, but long text with no `@` (digit runs, dotted or percent-encoded runs) is no longer rescanned 64 characters at a time. On 1.5 MB adversarial prompts this cuts prompt-protection scan time by up to 15x, and by about 35% on dash-separated digits.
- The entropy bonus is no longer computed for values too short to earn it (entropy is at most log2 of the length). A per-span dedupe set that could never match anything is gone.
