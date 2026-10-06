# Native acceptance assets in the portable kit

`run-support-matrix.mjs` and `../../scripts/verify-native-host-matrix-v6.mjs`
can run from this extracted directory with Node.js 24. The support matrix,
schema and scenario template are operator inputs. Template validation and a
version probe do not establish host enforcement or production acceptance.

`interception-matrix.json` is a source-evidence catalogue. Its source paths and
`verify-interception-matrix.mjs` commands require the complete frozen source
checkout delivered separately; that checker is intentionally absent from this
portable kit. Run it in that source checkout, not against the extracted kit.
The kit does not claim that source-path evidence or named host acceptance has
been verified merely by packaging this catalogue.
