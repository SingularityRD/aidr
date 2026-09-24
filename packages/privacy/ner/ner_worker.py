#!/usr/bin/env python3
"""Optional HF token-classification worker. No network, auto-download, pickle or remote code.
Model inference has NOT been executed in the delivered environment; see docs/VALIDATION.md.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from artifacts import verified_manifest, utf16_offsets, aggregate_tokens

for key, value in {'HF_HUB_OFFLINE':'1', 'TRANSFORMERS_OFFLINE':'1', 'HF_HUB_DISABLE_TELEMETRY':'1',
                   'DO_NOT_TRACK':'1', 'TOKENIZERS_PARALLELISM':'false'}.items():
    os.environ[key] = value

def send(value: dict) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=True, separators=(',', ':')) + '\n')
    sys.stdout.flush()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--threads', type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.threads <= 8:
        raise ValueError('INVALID_THREADS')
    manifest = verified_manifest(args.manifest, args.manifest_sha256)
    # Import only after artifact verification; dependencies are optional to the TS core.
    import torch
    from transformers import AutoModelForTokenClassification, AutoTokenizer
    from transformers.utils import logging
    logging.set_verbosity_error()
    logging.disable_progress_bar()
    torch.set_num_threads(args.threads)
    torch.set_num_interop_threads(1)
    models = []
    coverage = {}
    for spec in manifest['models']:
        tokenizer = AutoTokenizer.from_pretrained(spec['_root'], local_files_only=True, trust_remote_code=False, use_fast=True)
        if not tokenizer.is_fast:
            raise ValueError('FAST_TOKENIZER_REQUIRED')
        model = AutoModelForTokenClassification.from_pretrained(spec['_root'], local_files_only=True,
            trust_remote_code=False, use_safetensors=True).to('cpu').eval()
        length = spec.get('max_length', 384)
        if length > min(getattr(model.config, 'max_position_embeddings', 512), tokenizer.model_max_length):
            raise ValueError('WINDOW_TOO_LARGE')
        actual_types = set()
        for label in model.config.id2label.values():
            base = label[2:] if label.startswith(('B-', 'I-', 'E-', 'S-', 'L-', 'U-')) else label
            if base not in spec['label_map']:
                raise ValueError('UNMAPPED_LABEL')
            if spec['label_map'][base] is not None:
                actual_types.add(spec['label_map'][base])
        for language in spec['languages']:
            coverage.setdefault(language, set()).update(actual_types)
        models.append((spec, tokenizer, model))
    send({'ready': True, 'capabilities': {'local': True, 'offsetUnit': 'utf16',
        'languages': sorted(coverage), 'entities': sorted(set().union(*coverage.values())),
        'entitiesByLanguage': {lang: sorted(types) for lang, types in coverage.items()},
        'revision': args.manifest_sha256}})
    while True:
        line = sys.stdin.buffer.readline(8 * 1024 * 1024 + 1)
        if not line:
            return 0
        if len(line) > 8 * 1024 * 1024 or not line.endswith(b'\n'):
            return 2
        request = json.loads(line)
        text = request['text']
        if not isinstance(text, str) or len(text.encode('utf-8')) > 1024 * 1024:
            return 2
        mapping = utf16_offsets(text)
        entities = {}
        for spec, tokenizer, model in models:
            encoded = tokenizer(text, return_offsets_mapping=True, return_overflowing_tokens=True,
                truncation=True, max_length=spec.get('max_length', 384), stride=spec.get('stride', 96))
            covered = bytearray(len(text))
            with torch.inference_mode():
                for i, offsets in enumerate(encoded['offset_mapping']):
                    for start, end in offsets:
                        if not 0 <= start <= end <= len(text):
                            raise ValueError('INVALID_OFFSETS')
                        covered[start:end] = b'\x01' * (end - start)
                    tensors = {key: torch.tensor([encoded[key][i]], dtype=torch.long)
                               for key in tokenizer.model_input_names if key in encoded}
                    logits = model(**tensors).logits[0]
                    scores, ids = logits.softmax(-1).max(-1)
                    labels = [model.config.id2label[int(index)] for index in ids.tolist()]
                    spans = aggregate_tokens(text, offsets, labels, scores.tolist(), spec['label_map'])
                    for entity in spans:
                        key = (mapping[entity['start']], mapping[entity['end']], entity['type'])
                        previous = entities.get(key)
                        if previous is None or entity['score'] > previous['score']:
                            entities[key] = {'start': key[0], 'end': key[1], 'type': key[2], 'score': entity['score']}
                        if len(entities) > 2048:
                            raise ValueError('ENTITY_LIMIT')
            if any(not covered[i] and not char.isspace() for i, char in enumerate(text)):
                raise ValueError('INCOMPLETE_TOKEN_COVERAGE')
        send({'id': request['id'], 'complete': True, 'entities': list(entities.values())})

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # Never return raw exception messages / text / weights paths to the caller or logs.
        sys.stderr.write('NER_WORKER_FAILURE\n')
        raise SystemExit(2)
