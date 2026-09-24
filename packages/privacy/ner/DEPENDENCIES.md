# Optional inference dependencies

The TypeScript package and the Python artifact/offset tests have no third-party runtime dependencies.
`ner_worker.py` additionally needs an approved CPU PyTorch + Transformers + fast-tokenizer + safetensors environment.
No model inference dependency versions were installed or verified in the delivery environment; no pretend production lockfile is supplied for this optional worker.

Build a platform-specific, hash-pinned wheelhouse in a connected staging environment, run the real-model acceptance suite, scan its SBOM, then import it into the air-gapped environment. Runtime must have network egress denied at the OS/container level. HF offline flags are defense in depth, not a network sandbox.

Do not substitute a generic PER/ORG/LOC NER model and claim complete ADDRESS support. The defense profile requires PERSON and ADDRESS capabilities **separately for Turkish and English**. Those capability declarations still require independent quality evaluation.
