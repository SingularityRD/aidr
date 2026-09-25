# AI model supply-chain safety

Most model formats in the Python ecosystem are programs, not data. Loading a
`.pt`, `.pth`, `.ckpt`, `.pkl`, `.joblib`, a pickled `.bin`, a Keras model with
Lambda layers or a NumPy object array can run code chosen by whoever produced
the file. `trust_remote_code=True` runs Python that ships inside a model
repository. When an AI coding agent writes or runs such code, one unvetted
download can end in arbitrary code execution on the developer's machine or in
CI.

Singularity AIDR inspects the code an agent writes and the commands it runs for
unsafe model loading and unvetted model sources. It holds risky actions for
review (`ask`) and blocks the clearly dangerous combinations (`deny`). Every
reason names the safe alternative, which in almost every case is the
**`.safetensors`** format (tensors only, no code).

## What is detected

| Rule | Detects | Decision |
|------|---------|----------|
| AISC-001 | `torch.load(...)` without `weights_only=True` | ask |
| AISC-002 | `pickle` / `joblib` / `dill` / `cloudpickle` / `pandas.read_pickle` on a downloaded or remote file (hub download, `urlretrieve`, URL literal, response body, `download…` paths) | ask |
| AISC-003 | Unpickling straight from a network response (`pickle.loads(requests.get(url).content)`, `torch.load(urlopen(url))` without `weights_only=True`, `read_pickle("https://…")`) | deny |
| AISC-004 | A command that downloads a file and unpickles it in the same step (`curl … && python -c "…pickle.load…"`) | deny |
| AISC-005 | `trust_remote_code=True` in Python | ask |
| AISC-006 | `--trust-remote-code` / `trust_remote_code=True` in `--model_args` on the command line | ask |
| AISC-007 | `from_pretrained("org/model", trust_remote_code=True)` / `pipeline(model=…, trust_remote_code=True)` from an organisation outside the trusted list | deny |
| AISC-008 | `vllm serve org/model --trust-remote-code` (and similar CLIs) from an organisation outside the trusted list | deny |
| AISC-009 | Keras `load_model(..., safe_mode=False)` or `enable_unsafe_deserialization()` | ask |
| AISC-010 | `numpy.load(..., allow_pickle=True)` | ask |
| AISC-011 | `yaml.unsafe_load` or `yaml.load` with `Loader=yaml.Loader` / `UnsafeLoader` (model and training configs) | ask |
| AISC-012 | `huggingface-cli download`, `hf download`, `hf_hub_download`, `snapshot_download` from an organisation outside the trusted list | ask |
| AISC-013 | `curl` / `wget` / `urlretrieve` / `load_state_dict_from_url` of a weight file (`.pt .pth .pkl .pickle .ckpt .joblib .h5 .keras`, model-named `.bin`) from a host outside the trusted hubs | ask |
| AISC-014 | The same downloads over plain `http://`, from any host | ask |

The safe twins stay silent: `torch.load(path, weights_only=True)`,
`safetensors.torch.load_file(...)`, `np.load(path)`, `yaml.safe_load(f)`,
`joblib.load("model.joblib")` on a local artifact, and downloads from trusted
publishers and hubs.

`deny` rules use confidence 0.90–0.95, so the `relaxed` sensitivity preset turns
AISC-007/008 into `ask`; `paranoid` never relaxes them.

## Where it runs

The rules are part of the shared detection core, so every connector (Claude
Code, Cursor, VS Code, OpenClaw, OpenCode, Codex) applies them.

- **Code an agent writes**: Write, Edit, MultiEdit, apply_patch and NotebookEdit.
  Only the lines the call adds are inspected (an Edit that keeps an existing
  `torch.load` line untouched is not re-flagged), and Python rules apply only to
  Python files and notebook code cells, so documentation that mentions
  `torch.load(path)` is not flagged.
- **Code an agent runs**: `python -c "…"`, Python heredocs (`python - <<EOF`)
  and heredocs written into source files (`cat > train.py <<EOF`).
- **Commands**: model downloads, `--trust-remote-code` and download-then-load
  pipelines in Bash commands, shell scripts, Dockerfiles, Makefiles and CI YAML.
  A plain `grep "torch.load(" -r .` is not treated as loading a model.

## Trusted model sources

Shipped trusted sources live in `allowlists/model-sources/trusted-model-sources.yaml`:

- **Organisations** on the Hugging Face Hub (for example `meta-llama`, `google`,
  `microsoft`, `mistralai`, `Qwen`, `deepseek-ai`, `nvidia`,
  `sentence-transformers`). Matching is exact and case-insensitive.
- **Hosts** for direct weight downloads (`huggingface.co`, `hf.co`,
  `download.pytorch.org`, `tfhub.dev`, `kaggle.com`, `ngc.nvidia.com`,
  `modelscope.cn`), matched by suffix on a dot boundary.

A download is trusted only when **every** source it names is trusted: a trusted
download listed first cannot hide an untrusted one after it, a Hub URL is only
as trusted as the organisation in its path
(`huggingface.co/randomuser/x/resolve/main/model.bin` is still flagged), and
plain HTTP is never trusted. A trusted source only removes the "unvetted
source" finding: unsafe loading (AISC-001…011) is flagged whatever the source,
and `trust_remote_code=True` from a trusted publisher still asks (AISC-005).

Add your own organisations and hosts in `~/.singularity-aidr/config.json`:

```json
{
  "ai_supply_chain": {
    "trusted_model_orgs": ["my-company", "my-ml-team"],
    "trusted_model_hosts": ["models.internal.example.com"]
  }
}
```

If the shipped list cannot be read, nothing is trusted and the source rules keep
asking; a missing list never silently approves a download.

## Scanning an existing project

```bash
aidr scan --code .                 # human-readable, file:line per finding
aidr scan --code src notebooks --json
```

The scan runs the same rules (plus the [secure-code guardrails](secure-code-guardrails.md))
over every supported source file, reports `file:line` (and the cell for
notebooks), and never executes or uploads anything. Dependency, build-output and
virtual-environment directories are skipped and symbolic links are not
followed. Exit codes: `2` when a critical or high finding exists, `1` when part
of the scope could not be inspected, `0` otherwise, so the command can gate CI.
`disabled_threats` and `ai_supply_chain` from the local configuration apply.

## Tuning

- Disable a rule with `disabled_threats`, for example `["AISC-012"]`.
- Trust a publisher or host with `ai_supply_chain.trusted_model_orgs` /
  `trusted_model_hosts` instead of disabling a rule.
- An `ask` is released only through the operator approval channel
  (`aidr pending` / `aidr approve`) or the host's own confirmation dialog; the
  agent cannot approve its own action.

## Limitations

Detection is pattern-based. It recognises direct, idiomatic calls; it does not
follow data flow across files or through renamed functions (for example
`from torch import load as l`). It does not inspect the contents of model files
themselves and does not replace a model-artifact scanner in your registry.
