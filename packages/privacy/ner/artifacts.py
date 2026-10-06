"""Offline artifact verification. An approved manifest digest is the external trust anchor.
Hashes alone do not establish publisher identity, licensing or model quality.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any

TYPES = frozenset(('PERSON EMAIL PHONE TC_KIMLIK IBAN CREDIT_CARD ADDRESS US_SSN '
    'DATE_OF_BIRTH PASSPORT NATIONAL_ID TAX_ID BANK_ACCOUNT IP_ADDRESS MAC_ADDRESS '
    'SECRET PRIVATE_KEY INTERNAL CLASSIFIED LOCATION USERNAME HEALTH_ID LICENSE_PLATE').split())

class ArtifactError(Exception):
    pass

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def verified_manifest(path: Path, expected_digest: str) -> dict[str, Any]:
    if not re.fullmatch('[0-9a-f]{64}', expected_digest) or path.is_symlink():
        raise ArtifactError('INVALID_MANIFEST')
    if path.stat().st_size > 1024 * 1024 or sha256_file(path) != expected_digest:
        raise ArtifactError('MANIFEST_DIGEST_MISMATCH')
    data = json.loads(path.read_text(encoding='utf-8'))
    models = data.get('models')
    if data.get('version') != 1 or not isinstance(models, list) or not 1 <= len(models) <= 4:
        raise ArtifactError('INVALID_MANIFEST')
    for model in models:
        if model.get('aggregation', 'token') not in ('token', 'first_word'):
            raise ArtifactError('INVALID_AGGREGATION')
        raw_dir = Path(model['directory'])
        # Manifest paths are relative to its containing directory. No symlinks, traversal or downloads.
        if raw_dir.is_absolute() or '..' in raw_dir.parts or not raw_dir.parts:
            raise ArtifactError('UNSAFE_ARTIFACT_PATH')
        root = path.parent / raw_dir
        if not root.is_dir() or any(p.is_symlink() for p in [root, *root.parents] if p.exists()):
            raise ArtifactError('UNSAFE_ARTIFACT_PATH')
        inventory = model.get('files')
        if not isinstance(inventory, dict) or not inventory or len(inventory) > 256:
            raise ArtifactError('INVALID_INVENTORY')
        actual = set()
        for item in root.rglob('*'):
            if item.is_symlink():
                raise ArtifactError('SYMLINK_ARTIFACT')
            if item.is_file():
                relative = item.relative_to(root).as_posix()
                if item.suffix.lower() in {'.py', '.pyc', '.pkl', '.pickle', '.bin', '.pt', '.pth'}:
                    raise ArtifactError('UNSAFE_ARTIFACT_FORMAT')
                actual.add(relative)
        if actual != set(inventory):
            raise ArtifactError('INVENTORY_MISMATCH')
        if 'config.json' not in actual or not any(f.endswith('.safetensors') for f in actual):
            raise ArtifactError('MODEL_WEIGHTS_MISSING')
        if not any(f in actual for f in ['tokenizer.json', 'vocab.txt', 'spiece.model', 'sentencepiece.bpe.model']):
            raise ArtifactError('TOKENIZER_MISSING')
        for relative, digest in inventory.items():
            rel = Path(relative)
            if rel.is_absolute() or '..' in rel.parts or not re.fullmatch('[0-9a-f]{64}', digest):
                raise ArtifactError('UNSAFE_ARTIFACT_PATH')
            if sha256_file(root / rel) != digest:
                raise ArtifactError('ARTIFACT_DIGEST_MISMATCH')
        languages = model.get('languages')
        if not isinstance(languages, list) or not languages or not set(languages) <= {'tr', 'en'}:
            raise ArtifactError('INVALID_LANGUAGE')
        labels = model.get('label_map')
        if not isinstance(labels, dict) or not labels or any(v is not None and v not in TYPES for v in labels.values()):
            raise ArtifactError('INVALID_LABEL_MAP')
        max_len, stride = model.get('max_length', 384), model.get('stride', 96)
        if not isinstance(max_len, int) or not 32 <= max_len <= 512 or not isinstance(stride, int) or not 1 <= stride < max_len - 4:
            raise ArtifactError('INVALID_WINDOW')
        model['_root'] = str(root.resolve())
    return data

def utf16_offsets(text: str) -> list[int]:
    result = [0]
    for char in text:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF:
            raise ArtifactError('INVALID_UNICODE')
        result.append(result[-1] + (2 if cp > 0xFFFF else 1))
    return result

def encode_first_words(tokenizer, text: str, max_length: int, stride: int):
    """Align supervised first pieces to original words, including across overlapping windows."""
    words = list(re.finditer(r'\S+', text))
    values = [word.group() for word in words]
    options = dict(is_split_into_words=True, return_offsets_mapping=True, return_special_tokens_mask=True)
    full = tokenizer(values, truncation=False, **options)
    encoded = tokenizer(values, truncation=True, max_length=max_length, stride=stride,
                        return_overflowing_tokens=True, **options)

    def content(ids, offsets, word_ids, special):
        if not len(ids) == len(offsets) == len(word_ids) == len(special):
            raise ArtifactError('INVALID_WORD_ALIGNMENT')
        return [(i, (word, token, tuple(offset)))
                for i, (word, token, offset, skip) in enumerate(zip(word_ids, ids, offsets, special)) if not skip]

    complete = content(full['input_ids'], full['offset_mapping'], full.word_ids(), full['special_tokens_mask'])
    features = [feature for _, feature in complete]
    first = {}
    for i, (word, _, _) in enumerate(features):
        if type(word) is not int or not 0 <= word < len(words):
            raise ArtifactError('INVALID_WORD_ALIGNMENT')
        first.setdefault(word, i)
    if set(first) != set(range(len(words))):
        raise ArtifactError('INCOMPLETE_WORD_COVERAGE')
    eligible = set(first.values())
    absolute, projected, cursor = [], [], 0
    for i, local in enumerate(encoded['offset_mapping']):
        word_ids = encoded.word_ids(i)
        chunk = content(encoded['input_ids'][i], local, word_ids, encoded['special_tokens_mask'][i])
        if [feature for _, feature in chunk] != features[cursor:cursor + len(chunk)]:
            raise ArtifactError('INVALID_WORD_ALIGNMENT')
        offsets, word_offsets = [], [None] * len(local)
        for word, (start, end) in zip(word_ids, local):
            if word is None:
                if (start, end) != (0, 0):
                    raise ArtifactError('INVALID_WORD_ALIGNMENT')
                offsets.append((0, 0))
            else:
                if type(word) is not int or not 0 <= word < len(words) or not 0 <= start <= end <= len(words[word].group()):
                    raise ArtifactError('INVALID_WORD_ALIGNMENT')
                offsets.append((words[word].start() + start, words[word].start() + end))
        for j, (token_index, (word, _, _)) in enumerate(chunk):
            if cursor + j in eligible:
                word_offsets[token_index] = (words[word].start(), words[word].end())
        absolute.append(offsets)
        projected.append(word_offsets)
        stop = cursor + len(chunk)
        cursor = stop - stride
    if not encoded['offset_mapping'] or stop != len(features):
        raise ArtifactError('INCOMPLETE_WORD_COVERAGE')
    return encoded, absolute, projected

def aggregate_tokens(text: str, offsets: list[tuple[int, int]], labels: list[str], scores: list[float],
                     label_map: dict[str, str | None]) -> list[dict[str, Any]]:
    """Preserve predicted content and low confidence; normalize name/address whitespace after BIO grouping."""
    import math
    if not len(offsets) == len(labels) == len(scores):
        raise ArtifactError('INVALID_MODEL_OUTPUT')
    result: list[dict[str, Any]] = []
    current = None
    for (start, end), label, score in zip(offsets, labels, scores):
        if start == end == 0:
            continue
        if not 0 <= start < end <= len(text) or not math.isfinite(score) or not 0 <= score <= 1:
            raise ArtifactError('INVALID_MODEL_OUTPUT')
        base = label[2:] if label.startswith(('B-', 'I-', 'E-', 'S-', 'L-', 'U-')) else label
        if base not in label_map:
            raise ArtifactError('UNMAPPED_LABEL')
        entity_type = label_map[base]
        if entity_type is None:
            current = None
            continue
        begins = label.startswith(('B-', 'S-', 'U-'))
        if current is not None and not begins and current['type'] == entity_type and start >= current['end'] and not text[current['end']:start].strip():
            current['end'] = end
            current['score'] = min(current['score'], score)
        else:
            current = {'start': start, 'end': end, 'type': entity_type, 'score': score}
            result.append(current)
        if label.startswith(('E-', 'L-', 'S-', 'U-')):
            current = None
    # SentencePiece offsets may include the space before a name/address token.
    # Group first so whitespace-only B/O tokens still preserve entity boundaries.
    for entity in result:
        if entity['type'] in {'PERSON', 'ADDRESS'}:
            while entity['start'] < entity['end'] and text[entity['start']].isspace():
                entity['start'] += 1
            while entity['end'] > entity['start'] and text[entity['end'] - 1].isspace():
                entity['end'] -= 1
    return [entity for entity in result if entity['start'] < entity['end']]
