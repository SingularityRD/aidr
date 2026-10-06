# Reproducible local model staging and qualification

Real CPU inference was executed on Windows x64 CPython 3.12.10/Node 24.18.1 and Linux x86_64 CPython 3.11.2/Node 22.16.0 on 2026-10-06. The files below provide a working installation/evaluation path; **none of these public candidates is approved or qualified**. Weights, virtual environments, wheelhouses and corpus text are not included in the npm package. The configured service still requires its separately approved manifest digest. Aggregates, hashes, platform details and smoke outputs are recorded in [MODEL_PROVIDER_EVIDENCE.json](MODEL_PROVIDER_EVIDENCE.json).

## Pinned candidates and actual labels

| Candidate | Immutable revision | Declared licence | Inspected base labels / canonical mapping |
|---|---|---|---|
| [Ersan Bilik's Turkish KVKK BERT](https://huggingface.co/ersanbil/kvkk-pii-ner/blob/cb85fbd0839f92cff2ddc92c4f23ecf61cb769c2/README.md) | `cb85fbd0839f92cff2ddc92c4f23ecf61cb769c2` | Apache-2.0 | `PERSON→PERSON`, `ADDRESS→ADDRESS`, `HEALTH_DATA/KVKK_SPECIAL→INTERNAL`, `O→null` |
| [seongyeon1's DeBERTa PII classifier](https://huggingface.co/seongyeon1/pii-deberta-v3-base-multi/blob/9d83044fc56074f871ee811e7009778867beb7cf/README.md) | `9d83044fc56074f871ee811e7009778867beb7cf` | Apache-2.0 | `NAME_STUDENT→PERSON`, `STREET_ADDRESS→ADDRESS`, `EMAIL→EMAIL`, `USERNAME→USERNAME`, `PHONE_NUM→PHONE`, `ID_NUM/URL_PERSONAL→INTERNAL`, `O→null` |
| [aditrynacode's PrivyShield DistilBERT, initial comparison](https://huggingface.co/aditrynacode/privyshield-ner/blob/a3aa3695fb2998f32a750d581337610eafa079a3/README.md) | `a3aa3695fb2998f32a750d581337610eafa079a3` | Apache-2.0 | `PERSON_NAME→PERSON`, `ADDRESS→ADDRESS`, `O→null` |

The default `ner/public-models.lock.json` stages Turkish KVKK + DeBERTa. `ner/public-models.privyshield.lock.json` reproduces the initial pair. Both locks contain every selected file's size and SHA-256, including the original author card. Safe built-in Transformers architectures and actual checkpoint `id2label` sets are checked before a provider configuration is emitted. Training `.bin` files and remote Python model code are excluded. Extra sensitive labels map to the conservative `INTERNAL` policy rather than being discarded.

The Turkish card describes synthetic training and possible city/name confusion. The PrivyShield card describes English-only, India-centric synthetic training without manual annotations. The DeBERTa card describes English/French/German/Italian data, not Turkish; its broad `STREET_ADDRESS` training merge also includes geographic components. These are author claims and limitations, not independently verified quality evidence. Model/data licence declarations still require organizational legal review.

The worker currently runs every installed model on every input. Its language declarations describe available label coverage and do **not** route input to one model. Foreign-language false positives and overlapping canonical types must therefore be evaluated on the actual combined provider. Do not infer that a language/type readiness declaration proves accurate detection.

## Install in connected staging

Use an administrator-controlled directory and Python executable. For the measured Windows x64 CPython 3.12 environment, obtain exact wheels in connected staging, then install into a fresh environment without an index:

```powershell
python -m venv C:\staging\aidr-ner
C:\staging\aidr-ner\Scripts\python.exe -m pip download --only-binary=:all: --require-hashes --extra-index-url https://download.pytorch.org/whl/cpu -r ner/requirements.windows-py312.lock.txt -d C:\staging\wheelhouse
C:\staging\aidr-ner\Scripts\python.exe -m pip install --no-index --find-links C:\staging\wheelhouse --require-hashes -r ner/requirements.windows-py312.lock.txt
python ner/install_models.py --destination C:\staging\aidr-models --python C:\staging\aidr-ner\Scripts\python.exe
node scripts/platform/probe-ner.mjs C:\staging\aidr-models\local-provider.json C:\staging\probe.json
```

Run from the package directory. Other operating systems/Python versions need their own measured wheel lock. The supplied lock was replayed against a fresh environment with the local wheelhouse; it is not a vulnerability audit or production dependency approval.

`ner/requirements.linux-py311.lock.txt` separately pins 34 measured Linux CPython 3.11 wheels. In the existing test container (glibc 2.36), a fresh copied Python environment installed those wheels with `--no-index --require-hashes`, loaded the real BERT/DeBERTa safetensors and fast tokenizers, and executed the same three probes with Docker `--network none`, a read-only root and read-only package/model mounts. Both raw span boundaries and runtime decisions reproduced the Windows alternative probe; no Linux corpus-quality qualification is claimed. These are different measured runtime stacks. Linux regression tests using fake NER alone do not prove real learned inference.

For Linux staging, obtain the wheelhouse using `pip download --only-binary=:all: --require-hashes --extra-index-url https://download.pytorch.org/whl/cpu -r ner/requirements.linux-py311.lock.txt -d /staging/wheelhouse`, create a CPython 3.11 virtual environment, and install from that local wheelhouse with `--no-index --require-hashes`. Run `install_models.py` with its absolute Python executable, then run the same probe under the deployment's OS network restrictions. The Python executable and inference libraries require an executable runtime mount; model data can remain read-only. The measured container image identity is recorded in the evidence, not presented as an approved production base image.

The installer streams only immutable HTTPS artifacts, checks exact size/digest before publishing each file, rejects mismatched existing files, and verifies the final inventory. It writes `manifest.json` with `approved:false` and `qualificationStatus:independent-corpus-required`, plus an absolute `local-provider.json`. `--lock reviewed-lock.json` accepts administrator-supplied pinned replacements using the same schema. The worker loads only local verified safetensors/fast-tokenizer files with HF offline flags and remote code disabled. Import the reviewed files into an OS/container with outbound egress denied; offline flags alone do not prove network isolation.

## Measured smoke failures

The smoke and 600-document tables below preserve the initial measurements before the whitespace-boundary fix. The later source diagnosis and unchanged-gold comparison are recorded in the GO preparation section below and `MODEL_PROVIDER_GO_DIAGNOSTICS.json`.

The unchanged Turkish probe is `Ahmet Yılmaz, Atatürk Mahallesi 12. Sokak No: 5 Ankara adresinde yaşıyor.` Its synthetic gold is PERSON `[0,12)` and ADDRESS `[14,54)` in UTF-16.

Isolated Turkish KVKK emits PERSON `[0,12)` and **no ADDRESS**. Isolated PrivyShield emits PERSON `[0,7)`, ADDRESS `[7,34)` and `[36,72)` on that Turkish input. In the initial pair, overlapping findings become one ADDRESS mask over the sentence: the person's characters are masked, but exact PERSON typing/boundaries are lost. This is overmasking and recognition failure, not a demonstrated forwarded-person leak.

Replacing PrivyShield with DeBERTa preserves runtime PERSON/ADDRESS findings, with `review` on this case. Its raw ADDRESS spans `[13,35)` and `[47,54)` still omit part of the gold address. Existing deterministic address detection supplies full runtime masking. The English and emoji smoke cases also have full runtime masking but imperfect learned exact spans. `probe-ner.mjs` reports raw spans, exact matches, typed coverage, runtime mask coverage and decisions separately; it always reports `qualified:false`. Three developer-known cases cannot establish detection accuracy.

## Reproduce public comparison

`ner/public-corpora.lock.json` pins source data and author cards. `build_public_corpus.py` selects the first 100 eligible PERSON-positive, ADDRESS-positive and fully source-annotated clean documents per language, before inference, with no text/gold edits. It converts source code-point offsets to UTF-16.

* Turkish positives: [BTX24's Turkish privacy dataset](https://huggingface.co/datasets/BTX24/turkish-privacy-pii-ner/blob/45a8e18edb57224b14368c910f701e064dbb1326/README.md), CC-BY-4.0, publisher `test.jsonl`, revision `45a8e18edb57224b14368c910f701e064dbb1326`. Attribution: BTX24; changes are format/offset conversion and bounded source-order selection.
* Turkish clean documents: [Yusuf Said Çöpcü, Tunahan Yardımcı and Muhammet İbrahim Kaya's public dataset](https://huggingface.co/datasets/yusuf-said/turkish-privacy-filter-dataset/blob/fc2b9a3e197484d22a8201317cc722baacf053b7/README.md), MIT, revision `fc2b9a3e197484d22a8201317cc722baacf053b7`. Its only split is train-labelled; these negatives are **not** claimed to be a publisher-heldout split.
* English: [beki's Privy dataset](https://huggingface.co/datasets/beki/privy/blob/dc137a6a976f6b5bb8768e9bb51ec58df930ccd1/README.md), MIT, `test-small.json` inside the pinned ZIP, revision `dc137a6a976f6b5bb8768e9bb51ec58df930ccd1`. Only source `PER` and original `address`/`street_address` placeholders become PERSON/ADDRESS. Generic LOC, geographic components, other sensitive categories and inconsistent source annotations are excluded, preventing incomplete gold from becoming clean negatives. No dataset loader or archive paths are executed/extracted.

```powershell
python ner/build_public_corpus.py --download --source-directory C:\staging\public-corpus --output C:\staging\comparison.jsonl
node scripts/platform/qualify-ner.mjs C:\staging\comparison.jsonl C:\staging\aidr-models\local-provider.json ner/qualification-policy.example.json C:\staging\comparison-report.json
```

The corpus provenance sidecar records source hashes, selection counts and split limitations. All records retain `origin:synthetic`, so this comparison cannot pass the independent-corporate gate. Training overlap with model publishers is unverified. Public synthetic labels are not a substitute for domain annotation review.

The measured 600-document comparison used corpus SHA-256 `1c94a485923445a0c5a7b49919e5cb39fc619fbb2753e5c5768deecca85080a1`. Exact true positives below have denominators shown; clean disruption is a document count. Neither pair passes any required language/type recall/precision gate or the clean-rate gate.

| Pair / scope | TR PERSON | TR ADDRESS | EN PERSON | EN ADDRESS | TR clean disrupted | EN clean disrupted |
|---|---:|---:|---:|---:|---:|---:|
| KVKK + PrivyShield, raw NER | 78/100 | 1/100 | 33/108 | 36/107 | 100/100 | 100/100 |
| KVKK + PrivyShield, defense runtime | 2/100 | 0/100 | 33/108 | 35/107 | 100/100 | 100/100 |
| KVKK + DeBERTa, raw NER | 78/100 | 0/100 | 63/108 | 8/107 | 98/100 | 94/100 |
| KVKK + DeBERTa, defense runtime | 24/100 | 0/100 | 63/108 | 48/107 | 98/100 | 96/100 |

Any-type runtime masking coverage is reported independently:

| Pair / language | Gold spans covered by any mask | Positive allow/redact documents | Incomplete gold in allow/redact output | Positive block/review documents |
|---|---:|---:|---:|---:|
| KVKK + PrivyShield / TR | 187/200 | 64 | 3 | 136 |
| KVKK + PrivyShield / EN | 169/215 | 6 | 1 | 194 |
| KVKK + DeBERTa / TR | 167/200 | 69 | 11 | 131 |
| KVKK + DeBERTa / EN | 161/215 | 31 | 0 | 169 |

These incomplete masks are additional candidate failures. Denied documents are not counted as accurate recognition, and zero incomplete English forwardable outputs in the alternative does not erase its Turkish misses or excessive clean disruption. The existing thresholds and original gold were retained throughout.

Five representative clean source rows were audited against **all** original annotation categories: Turkish records `tr_web_00382`, `tr_web_10398`, `tr_web_10389`; Privy test-small templates `103249`, `13346`. Their source non-O label sets are empty and rules-only scans allow them with no findings. The initial pair's raw learned PERSON/ADDRESS spans cause `REVIEW_REQUIRED`; an unapproved-manifest flag does not cause this offline evaluation decision. On these rows, isolated PrivyShield emits 18/17/17/11/8 spans, isolated KVKK 1/0/0/1/5, and isolated DeBERTa 2/2/2/2/3. This separates model/cross-language false positives from configuration gates, while preserving the public annotation limitations.

## GO preparation source diagnosis

The same 600 public documents were inferred independently by each of the three cached models. A genuine aggregation boundary defect was found: DeBERTa SentencePiece offsets include a leading space, e.g. `▁Rajesh` covers `[10,17)` including the blank before the name. `aggregate_tokens` now trims outer whitespace from completed PERSON/ADDRESS spans **after** BIO grouping. It retains every non-whitespace character, internal whitespace, punctuation, combining/zero-width characters, confidence scores and B/I/O boundaries. Other sensitive types keep their existing content contract. Three added regression checks bring the Python suite to 50 passing tests.

Replay over the completed cached BIO predictions changed 684 DeBERTa spans and no KVKK/PrivyShield spans. Against identical gold and policy, the alternative pair's raw TR PERSON exact TP improves from 78 to 82/100 and FP from 214 to 209. TR ADDRESS remains 0/100; EN PERSON stays 63/108 and ADDRESS 8/107. Clean disruption stays TR 98/100 and EN 94/100. An exhaustive check across all 600 rows/model verifies that normalization preserves all non-whitespace typed character coverage. Span coverage that counts whitespace can decrease between separate B entities; that change does not mean previously masked letters/digits became exposed.

The foreign-language amplification is real, while genuine quality failures also remain. These **diagnostic subsets do not implement runtime routing**:

| Isolated model / its declared language | PERSON exact TP | ADDRESS exact TP | Clean disruption |
|---|---:|---:|---:|
| KVKK / TR | 78/100 | 0/100 | 2/100 |
| PrivyShield / EN | 33/108 | 36/107 | 99/100 |
| DeBERTa / EN | 63/108 | 8/107 | 66/100 |

In representative original `btx-test-2`, KVKK predicts `O` across every gold address token, including the street, number, neighborhood and city, with scores 0.775–0.994. Offset normalization cannot recover an entity the model did not predict. A safe language-routing change does not follow from capability metadata alone: the IPC request currently contains text, with no independently trusted language restriction, and mixed-language content remains possible. No language guessing, confidence filtering, BIO-boundary merging, training or new model framework was introduced.

The live worker after the fix reproduces the three smoke decisions (`review`, `redact`, `review`) with complete runtime masking and valid UTF-16 offsets; learned address gaps persist. [MODEL_PROVIDER_GO_DIAGNOSTICS.json](MODEL_PROVIDER_GO_DIAGNOSTICS.json) records source hashes, actual models, complete aggregate before/after reports and the live probe. Its after metrics replay the source normalization over cached predictions; they are not a full after-fix runtime corpus benchmark. Historical initial failures remain in `MODEL_PROVIDER_EVIDENCE.json`. Both pairs remain unapproved and unqualified; this source fix prepares the portable installer/evaluation package without granting deployment authority.

## Further pipeline and model-quality diagnosis

The three pinned checkpoints load without missing, unexpected or mismatched weights. Their classifier sizes, inverse label maps and tokenizer vocabulary sizes agree. The worker now rejects any checkpoint loading discrepancy before advertising readiness, preventing a future incomplete checkpoint from silently using newly initialized weights. Seven focused startup/tokenizer checks bring the isolated Python suite to 57 passing tests. Both original and alternative pairs also started and inferred with the actual cached Windows runtime after this change.

A separate preprocessing defect was found in Transformers 5.13: its DeBERTa tokenizer constructor replaces the normalizer serialized in the verified `tokenizer.json`. For example, fullwidth `Ａｌｉｃｅ` becomes `[UNK]` instead of the pinned `▁Alice` token. The worker now restores only that verified normalizer and checks its exact serialized value, failing startup if restoration does not reproduce it. Actual tests compare all full token IDs, offsets and overflow windows against each original tokenizer on all 600 documents/model, plus fullwidth, non-breaking-space, Roman-numeral and emoji inputs. All match. **The normalization defect changes none of the 600 benchmark inputs**, so this fix does not improve their measured qualification metrics. No learned Linux runtime rerun is claimed for this later worker change.

Raw logits reproduce the authors' inference paths on representative cases. KVKK emits `O` on all gold address tokens in `btx-test-2` and `btx-test-11`, and omits ADDRESS on a simple structured address control. Its own-language ADDRESS predictions overlap 50/100 gold spans but fully cover the non-whitespace content of none. Some PERSON losses are real omitted tokens; others are annotation-boundary differences such as a gold name including `Dr.`. PrivyShield emits high-confidence PERSON/ADDRESS findings on clean SQL identifiers even on inputs shorter than its documented 64-token maximum. DeBERTa often emits separate B entities for first/last names and separate street/city/postcode components, consistent with its card's source-label merges; broad ID predictions account for most of its own-language clean findings. These are model/generalization and annotation-semantics limitations, rather than missing model weights or an offset conversion explanation.

The [PrivyShield author training/inference code](https://github.com/aditrynacode/PrivyShield/blob/95a73338b0ad907ab6b751c58e79db0fc902df94/NER/train.py) uses max length 64. A diagnostic rerun used 64-token padded windows with stride 16 and checked complete input coverage across the same 600 documents. In its English subset, PERSON exact TP improves 33→40/108 and ADDRESS 36→47/107, while clean disruption remains 99/100 and precision remains about 0.044/0.0083. The combined pair remains unqualified. This measured trial does not change the locked/default window configuration, acceptance thresholds or gold. No confidence filtering or language guessing was added.

[MODEL_QUALITY_DIAGNOSTICS.json](MODEL_QUALITY_DIAGNOSTICS.json) records checkpoint diagnostics, immutable author-source references, original/restored tokenizer receipts, the full window trial aggregates, source hashes and current actual worker probes. Raw corpus/token traces remain in ignored local scratch `.tmp-test/model-quality-2026-10-06/privacy`; they are not shipped. Earlier T38 and GO measurements remain historical evidence. The public candidates still fail model quality and remain unapproved.

## Independent qualification and approval

Supply a separately held-out, fully annotated TR/EN domain JSONL corpus in the `GoldSample` format documented by `src/platform/evaluation.ts` (`id`, `documentId`, `language`, `origin`, `text`, `spans`). Provide the training JSONL as the optional fifth argument to check document/text overlap. The runner checks all required metrics separately for raw NER and complete defense behavior; rules cannot hide weak learned recognition. `runtimeCoverage` additionally measures the union of masking intervals regardless of their types, incomplete gold in allow/redact outputs, and denied positive documents. Wrong typing remains a recognition error even when another mask covers the characters; blocking/reviewing is counted separately. “Forwarded” aggregate counts mean an allow/redact result with non-null output; this offline runner performs no network send. Reports contain aggregates/hashes, not raw corpus text.

`ner/qualification-policy.example.json` declares the existing configurable engineering example: 100 positive spans for each language/type, 100 clean documents in each language, recall Wilson lower bound 0.95, precision Wilson lower bound 0.90 and observed clean disruption at most 0.05. `block`, `review` and `redact` all count as clean disruption. These values are not an official mandate or certification. The runner cannot authenticate operator-declared provenance or confer institutional approval; qualifying a report does not edit/approve a manifest or service configuration. Distribute the approved digest through the existing trusted configuration process only after actual acceptance.

After independent acceptance and organizational approval, the service requires the final manifest to explicitly contain `approved:true` and `qualificationStatus:"qualified"`, with its exact raw-byte SHA-256 independently configured as the approved digest. Missing, false or ambiguous approval fields and a mismatching digest refuse startup before the worker starts. The installer continues to emit `approved:false` and `independent-corpus-required`; the public comparison below cannot authorize changing those fields.

## Additional real candidates and corrected output contracts

The default two-model lock remains unchanged. Two optional, unapproved staging locks provide additional measured candidates:

| Optional lock | Pinned model | Actual output contract |
|---|---|---|
| `ner/public-models.cosmos.lock.json` | [YTU-COSMOS ModernBERT Turkish PII](https://huggingface.co/ytu-ce-cosmos/modernbert-tr-pii-ner/blob/69b2563bf18126fc3285ac2c66371b483bb6d7ec/README.md), `69b2563bf18126fc3285ac2c66371b483bb6d7ec`, Apache-2.0 | TR only; `KISI_AD_SOYAD→PERSON`, `ADRES→ADDRESS`; remaining sensitive/unrepresented labels map to canonical types or `INTERNAL`. Explicit `aggregation:"first_word"` matches the author's supervised first WordPiece for each original whitespace word. |
| `ner/public-models.openai-privacy-filter.lock.json` | [OpenAI privacy-filter](https://huggingface.co/openai/privacy-filter/blob/7ffa9a043d54d1be65afb281eddf0ffbe629385b/README.md), `7ffa9a043d54d1be65afb281eddf0ffbe629385b`, Apache-2.0 | Native installed Transformers architecture; PERSON/ADDRESS, EMAIL/PHONE/SECRET and conservative `INTERNAL` mappings. Hash-bound zero-bias default calibration and constrained BIOES decoding are mandatory. |

COSMOS's [pinned training loader](https://github.com/mrbesher/bertfinetuner/blob/34c279bd1319ed31643ba805fedb7e73b57e5591/src/bertfinetuner/data.py) excludes continuation subwords and special tokens from loss/evaluation. Interpreting their independently predicted labels as trained decisions was a real output-contract defect. The explicit profile keeps original word boundaries, confidence, BIO grouping and UTF-16 offsets; full-token alignment prevents promoting a continuation at an overflow-window start. Every non-whitespace character must still be token-covered. Invalid profiles/alignment refuse processing. Existing models retain their `token` default.

OpenAI's [pinned decoder](https://github.com/openai/privacy-filter/blob/f7f00ca7fb869683eb732c010299d901457f19c3/opf/_core/decoding.py) supplies the BIOES start/end/transition constraints; the local implementation uses no additional inference dependency. Unsupported calibration settings refuse startup. The installer accepts the built-in native architecture and caps safetensors files at 4 GiB, other selected files at 2 GiB; exact declared sizes, hashes, safe inventories and disabled remote code remain enforced. The 2,798,989,498-byte checkpoint was actually downloaded, verified and run locally; no cloud inference was used.

Actual frozen-worker raw-NER inference on the identical 600 records and unchanged policy gives:

| Candidate / profile | TR PERSON | TR ADDRESS | TR clean disrupted | EN PERSON | EN ADDRESS | EN clean disrupted |
|---|---:|---:|---:|---:|---:|---:|
| COSMOS original token argmax, diagnostic | 39/100 | 29/100 | 28/100 | 35/108 | 19/107 | 24/100 |
| COSMOS corrected first-word profile, conservative mappings | 43/100 | 72/100 | 4/100 | 0/108 | 0/107 | 5/100 |
| OpenAI native constrained BIOES default | 48/100 | 7/100 | 87/100 | 85/108 | 51/107 | 41/100 |

These are raw NER measurements, not a new full-defense-runtime benchmark. COSMOS declares only Turkish coverage; its English column is a diagnostic of applying its Turkish word-boundary contract outside that declared language, not English support. Every candidate still fails the exact recall/precision gates, and OpenAI fails the clean-rate gates. No confidence filtering, label dropping, gold edits, acceptance-threshold changes or training on the evaluation corpus was used. The synthetic provenance and unverified training overlap remain independent blockers. `docs/MODEL_CANDIDATE_EVIDENCE.json` retains the measured aggregates, complete source/model hashes, author-equivalence comparisons and scope limitations.

To stage one optional candidate, substitute its reviewed lock without approving the result:

```sh
python ner/install_models.py --lock ner/public-models.cosmos.lock.json --destination /staging/cosmos --python /staging/ner/bin/python3
python ner/install_models.py --lock ner/public-models.openai-privacy-filter.lock.json --destination /staging/openai-filter --python /staging/ner/bin/python3
node scripts/platform/qualify-ner.mjs /staging/gold.jsonl /staging/openai-filter/local-provider.json ner/qualification-policy.example.json /staging/qualification.json /staging/train.jsonl
```

The isolated Turkish candidate alone cannot satisfy the service's required TR/EN defense capabilities. A combined provider still runs all installed models on every input and needs its own qualification; capability declarations do not authorize guessed language routing. The remaining production input is a model that actually passes fully annotated, independently held-out TR/EN organizational acceptance, together with its reviewed runtime/artifact inventory and institutional approval. The new output fixes and reproducible installers do not supply that authority or erase the measured failures.
