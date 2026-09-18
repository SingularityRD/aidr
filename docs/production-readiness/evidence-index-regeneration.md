# The evidence index self-reference loop

**Audience:** whoever regenerates `docs/production-readiness/v8-evidence-index.json` next.

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
1. pnpm build:release                     # release artifacts, clears source maps
2. node scripts/refresh-claim-evidence.mjs
                                          # rebinds claim records to current HEAD;
                                          # exits 1 when the claim gate has open
                                          # findings — that is a finding, not a
                                          # failure of the refresh
3. commit FEATURE_INVENTORY.json, PRODUCTION_SALES_GAPS.json, and any
   build-derived file the run touched
                                          # this moves HEAD; that is expected
4. run every gate at the NEW HEAD
                                          # the stamps now match the tree that
                                          # will be described
5. node scripts/generate-v8-evidence-index.mjs --out <index>
                                          # generate, and do NOT commit
                                          # the index if you want the stamps
                                          # inside it to stay valid
6. leave the index uncommitted, or accept that committing it sets every
   stamp back to unknown until step 4 runs again
```

Step 6 is the real choice. Committing the index gives a durable record of a
green run at a known commit, at the cost of the index no longer describing the
tree it is committed into. Leaving it uncommitted keeps the stamps valid but the
record lives only on this machine — and `docs/production-readiness/v8-evidence-index.json`
is tracked, so "uncommitted" means "the working tree disagrees with the commit".

## What was chosen here, and why

The index is committed, and it therefore reads `unknown` when regenerated against
a later `HEAD`. That is honest: the stamps in it describe `ab55e2ba`, which is
recorded, and a reader who regenerates at a different commit is told the
difference rather than shown a stale `PASS`.

The alternative — removing `source_commit` from the generated inventories so
committing them does not move `HEAD` — would break the property that matters
more: that a generated inventory can be checked against the revision it claims to
describe. The loop is the price of that property, and the price is a documented
procedure rather than a silent `PASS`.
