# The evidence index self-reference loop

**Audience:** whoever regenerates `.release-evidence/v8-evidence-index.json` next.

## The symptom

Gates run and pass, the index is generated, and then every gate reads back as
`unknown` — with `observed_effect` naming a commit mismatch:

```
result source commit ab55e2ba... does not match current commit cf3cb48b...
no PASS was derived from the log
```

It looks like the gate runner is broken. It is not. It is working exactly as
designed, and the design has a loop in it.

## Why it happens

Three things are true at once:

1. `FEATURE_INVENTORY.json` and `PRODUCTION_SALES_GAPS.json` embed their own
   `source_commit` — the commit they were generated from.
2. `26-generator-determinism` fails unless those files are committed, because it
   compares the working tree against what the generator produces.
3. Every gate result file is stamped with the commit and candidate digest it ran
   against, and the index refuses to derive a `PASS` from a result whose stamp
   does not match the tree it is describing.

So: running the gates dirties the inventories → committing the inventories moves
`HEAD` → moving `HEAD` invalidates every gate stamp → the index reports `unknown`.
Regenerating the index and committing *that* moves `HEAD` again, and the loop
closes on itself.

The mismatch is not a bug. A result from `ab55e2ba` genuinely says nothing about
`cf3cb48b`, even when the only difference between them is a hash written into a
generated file. Deriving a `PASS` across that boundary is precisely the
provenance inflation the binding exists to prevent.

## The procedure that terminates

Order matters. Do the gate runs last, and do not commit anything after them.

```
node scripts/run-evidence-gates.mjs
```

That one command performs the whole sequence:

```
1. pnpm build:release                     # release artifacts, clears source maps;
                                          # refuses to continue if it leaves
                                          # non-generated source changes behind
2. rebuild the release candidate from the
   settled release dist                   # claim records are stamped with its
                                          # digest, so it must exist and match
                                          # before anything binds to it
3. node scripts/refresh-claim-evidence.mjs
                                          # rebinds claim records to the candidate
                                          # and commit that will be described;
                                          # exits 1 when the claim gate has open
                                          # findings — a finding, not a failure
4. run every gate sequentially            # together they race on the core build
                                          # lock and the shared dist trees
5. node scripts/generate-v8-evidence-index.mjs --out .release-evidence/v8-evidence-index.json
                                          # generate, and do NOT commit
6. print the verdict and stop             # PASS/FAIL/unknown per gate
```

Step 5 writes the canonical index under `.release-evidence/`. It stays bound to
the commit it describes, and CI uploads that directory as the durable run
artifact. `pnpm evidence:index:verify` does not rewrite the index: it validates
the schema and checks the recorded commit, candidate, declared-artifact hashes,
and captured-log hashes against the current checkout. It fails if any bound
evidence is missing or stale.

### Ordering constraints the orchestrator encodes

Three of these were discovered by getting them wrong, and each one produced a
failure that looked like a product defect:

- **The determinism gate runs last.** It asserts the inventories match what the
  generators produce, and gates 02 and 03 regenerate those very files. Running it
  in declaration order failed on drift an earlier gate in the same run had just
  created.
- **The candidate is rebuilt before the claim records are rebound.** Claim records
  carry the candidate inventory digest they scanned; rebuilding the candidate
  afterwards invalidates the records the refresh just wrote.
- **Prior evidence and kit outputs are preserved.** The runner checks its fixed
  output paths before the build and checks the kit paths again before assembly.
  It stops on a collision; retry from a fresh isolated worktree rather than
  clearing, renaming or overwriting an earlier run.

### Guard agreement

Two guards inspect the same derived files and must agree about which of them are
"generated output" rather than source: `scripts/build-release-candidate.mjs`
(refuses to assemble from a dirty tree) and this orchestrator (refuses to run on
an unsettled tree). When they disagreed, a full rehearsal was impossible in either
order — one demanded a commit the other had just called noise. The list they share
is: `.release-evidence/`, `.e2e-artifacts/`, `release-output/`, every package
`dist/`, `packages/core/src/generated/aig-*`, the two inventories, and the
evidence index.

## What was chosen here, and why

The index is generated under `.release-evidence/` and is never committed. This
keeps one candidate-bound authority instead of a live run artifact plus a stale
tracked duplicate.

The alternative — removing `source_commit` from the generated inventories so
committing them does not move `HEAD` — would break the property that matters
more: that a generated inventory can be checked against the revision it claims to
describe. The loop is the price of that property, and the price is a documented
procedure rather than a silent `PASS`.
