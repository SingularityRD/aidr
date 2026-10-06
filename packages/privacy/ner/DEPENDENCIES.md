# Optional inference dependencies

The TypeScript package and the Python artifact/offset tests have no third-party runtime dependencies.
`ner_worker.py` additionally needs an approved CPU PyTorch + Transformers + fast-tokenizer + safetensors environment.
A Windows x64 CPython 3.12 CPU environment was installed and replayed offline on 2026-10-06 using `requirements.windows-py312.lock.txt` and a local wheelhouse. The lock contains the exact wheel SHA-256 values measured for that platform. PyTorch 2.14.1+cpu, Transformers 5.13.0, tokenizers 0.22.2 and safetensors 0.8.0 loaded the pinned public candidates. This is reproducibility evidence for the measured environment, not approval, a security audit or a lock for Linux/other Python versions. See `../docs/MODEL_PROVIDER.md` for installation and qualification.

`requirements.linux-py311.lock.txt` pins a separate 34-wheel CPython 3.11/x86_64 environment. Its fresh hash-checked installation and real candidate inference were executed in the existing glibc 2.36 Linux test container with Docker network mode `none` and read-only package/model mounts. Model smoke boundaries/decisions reproduced the Windows alternative; domain qualification still fails. Neither lock nor the test container is an institution-approved deployment artifact.

Build a platform-specific, hash-pinned wheelhouse in a connected staging environment, run the real-model acceptance suite, scan its SBOM, then import it into the air-gapped environment. Runtime must have network egress denied at the OS/container level. HF offline flags are defense in depth, not a network sandbox.

Do not substitute a generic PER/ORG/LOC NER model and claim complete ADDRESS support. The defense profile requires PERSON and ADDRESS capabilities **separately for Turkish and English**. Those capability declarations still require independent quality evaluation.
