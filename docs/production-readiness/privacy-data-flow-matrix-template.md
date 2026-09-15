# Privacy data-flow matrix template

Status: **OPEN / SOURCE-GROUNDED TEMPLATE**

The machine-readable template is [`privacy-data-flow-matrix.json`](./privacy-data-flow-matrix.json), and its shape is defined by [`privacy-data-flow-matrix.schema.json`](./privacy-data-flow-matrix.schema.json). Run the local validator from the repository root:

```sh
pnpm verify:commercial-compliance
```

## How to complete a row

Keep one row per distinct source-to-destination flow. Replace an `unknown` value only when the value has been observed or supplied for the deployment being recorded. Do not replace it with a blank, `TBD`, or a guessed provider.

| Column | Required local input |
|---|---|
| `flow_id` | Stable `DF-###` identifier, never reused for a different flow |
| `data_class` / `fields` | Data category and field-level names or a field-level `unknown` marker |
| `source` / `purpose` / `trigger` | Source boundary, purpose, and event that starts the flow |
| `destination` / `destination_domain` | Actual receiving system and host, not a product model |
| `region` / `subprocessor` | Deployment-specific placement and processor record, or `unknown` |
| `lawful_basis` | Deployment-specific recorded basis, or `unknown` |
| `retention` / `deletion` | Retention interval and deletion behavior, or `unknown` |
| `access` / `transfer_mechanism` | Access role and transfer path, or `unknown` |
| `evidence` | Repository-local measurement or external receipt reference, or `unknown` |
| `status` | `inventory` while facts remain unresolved; `measured` only when all row facts are known; `accepted` only after the row is complete |
| `unknowns` | Exact field paths that still contain `unknown` |

The top-level `unknowns` list records unresolved matrix-wide inputs such as deployment scope. The top-level `limitations` list records what this file cannot establish. The validator permits an open template, but rejects an `accepted` matrix or accepted/measured row that still contains unknowns.

This artifact is a local documentation and validation aid. It does not establish a deployed destination, location, retention outcome, or external approval.
