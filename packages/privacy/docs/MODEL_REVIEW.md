# Model review — 23 September 2026

This is a public model-card/file review, not a real-model accuracy or latency benchmark. No external model code or weights were copied into the TypeScript core. No model is licensed or approved for the customer's specific defense deployment merely by being listed here.

## 1. tugrulkaya/turkish-pii-detector

The supplied card describes Turkish PERSON, EMAIL, PHONE, TC_KIMLIK, IBAN, CREDIT_CARD and ADDRESS detection and lists OpenRAIL. At review time the visible `main` tree (abbreviated revision `8f4070d`) was about 11.9 kB and contained `.gitattributes`, `README.md`, `config.json`, `inference.py` and `model_card.md`. It did not contain model weights or a tokenizer. The inference script's executable demo comments out model loading and explicitly simulates outcomes.

Decision: **not accepted as a runnable pretrained dependency**. This finding is limited to the reviewed public revision, not a claim about unpublished artifacts or every future revision. Obtain real, immutable model/tokenizer artifacts, training/evaluation provenance and the actual full license terms before reconsidering. A generic OpenRAIL tag is not a substitute for reviewing use restrictions.

Sources:
- https://huggingface.co/tugrulkaya/turkish-pii-detector
- https://huggingface.co/tugrulkaya/turkish-pii-detector/tree/main
- https://huggingface.co/tugrulkaya/turkish-pii-detector/blob/main/inference.py

## 2. urchade/gliner_multi_pii-v1

The card lists Apache-2.0, multilingual PII and label-configurable entity recognition, including person/address and many identifiers. This is a candidate for a broader independently evaluated model layer. The review does not establish Turkish defense-domain recall, model speed or suitability for a specific deployment.

Decision: **evaluation candidate only**, not bundled or executed. GLiNER requires its own inference adapter; the included HF AutoModelForTokenClassification worker is not a GLiNER implementation. No claim that a GLiNER integration has been delivered.

Source: https://huggingface.co/urchade/gliner_multi_pii-v1

## 3. dslim/distilbert-NER

The card lists Apache-2.0 and an approximately 66-million-parameter English NER model. Its ordinary entity categories are PER, ORG, LOC and MISC. It is a possible lightweight English PERSON baseline, not a full bilingual PII system.

Decision: **English PERSON baseline candidate only**. Generic LOC must not be relabeled as full ADDRESS just to pass capability checks. Pairing models requires true type coverage, appropriate licenses and held-out validation.

Source: https://huggingface.co/dslim/distilbert-NER

## 4. iiiorg/piiranha-v1-detect-personal-information

The card lists CC-BY-NC-ND-4.0, a 256-token context and English/Spanish/French/German/Italian/Dutch. Turkish is not among the listed supported languages. Card-reported scores are publisher-reported results, not reproduced results of this delivery.

Decision: **not selected as a default commercial AIDR dependency**. Non-commercial/no-derivatives conditions require appropriate permission and legal review before commercial adaptation/distribution. No real-model comparison was run.

Source: https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information

## Architecture reference

Presidio was reviewed as an example of extensible hybrid recognition/anonymization, not copied or added as a Python runtime dependency to the lightweight core.

Source: https://github.com/data-privacy-stack/presidio

## Technical standards references

IBAN check-digit/registration context: https://www.swift.com/standards/data-standards/iban-international-bank-account-number

US SSN excluded area/group/serial context: https://www.ssa.gov/employer/randomization.html

HF token-classification API reference: https://huggingface.co/docs/transformers/main_classes/pipelines

## Comparator supplied by the user

The attached Blacksight page describes local scanning, PII/secrets/custom patterns and block/redact/warn policy. Those descriptions motivated the core feature selection. The supplied text's claims about product counts, customer results, deployment time, certificates or TLS behavior were not independently validated and are not claims about this module.

Included here: local decision core, PII/secret rules, custom literal rules, masking, deny/review policies and metadata-only audit records.

Not included here: browser extension, endpoint interception, gateway appliance, SSO dashboard, centralized policy delivery, SIEM/webhook transport or 300+ verified application integrations.
