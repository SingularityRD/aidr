#!/usr/bin/env python3
"""Reproduce a bounded public synthetic comparison, never corporate qualification.
Reads pinned data only; does not execute dataset scripts or extract ZIP paths.
"""
import argparse
import json
import re
import zipfile
from collections import Counter
from pathlib import Path
from artifacts import ArtifactError, sha256_file, utf16_offsets
from install_models import download_file


def privy_spans(row):
    """Recover the original typed placeholders, so generic LOC is never ADDRESS.
    Reject source rows whose values, offsets and masked literals disagree.
    """
    spans = sorted(row['spans'], key=lambda s: (s['start_position'], s['end_position']))
    matches = list(re.finditer(r'\{\{([A-Za-z0-9_]+)\}\}', row['masked']))
    if len(spans) != len(matches):
        return None
    original_cursor = masked_cursor = 0
    result = []
    for span, match in zip(spans, matches):
        start, end = span['start_position'], span['end_position']
        if not 0 <= original_cursor <= start <= end <= len(row['full_text']) or row['full_text'][start:end] != span['entity_value']:
            return None
        if row['full_text'][original_cursor:start] != row['masked'][masked_cursor:match.start()]:
            return None
        original_cursor, masked_cursor = end, match.end()
        kind, key = span['entity_type'], match.group(1)
        if kind == 'O':
            continue
        if kind == 'PER':
            canonical = 'PERSON'
        elif kind == 'LOC' and key in {'address', 'street_address'}:
            canonical = 'ADDRESS'
        else:
            return None  # Other PII or geographic components would leave incomplete gold.
        if start == end:
            return None
        result.append({'start': start, 'end': end, 'type': canonical})
    if row['full_text'][original_cursor:] != row['masked'][masked_cursor:]:
        return None
    return result


def build(source: Path, lock: dict, count: int):
    if not 1 <= count <= 200:
        raise ArtifactError('PUBLIC_CORPUS_LIMIT')
    for dataset in lock['datasets']:
        for name, spec in dataset['files'].items():
            path = source / name
            if path.is_symlink() or path.stat().st_size != spec['size'] or sha256_file(path) != spec['sha256']:
                raise ArtifactError('PUBLIC_CORPUS_DIGEST_MISMATCH')
    selected, totals = [], Counter()
    def add(prefix, index, language, text, spans, document=None):
        group = 'clean' if not spans else '+'.join(sorted({s['type'] for s in spans}))
        if group not in {'clean', 'PERSON', 'ADDRESS'}:
            return
        key = language + ':' + group
        if totals[key] >= count:
            return
        mapping = utf16_offsets(text)
        converted = [{'start': mapping[s['start']], 'end': mapping[s['end']], 'type': s['type']} for s in spans]
        selected.append({'id': f'{prefix}-{index}', 'documentId': f'{prefix}-{document if document is not None else index}',
                         'language': language, 'origin': 'synthetic', 'text': text, 'spans': converted})
        totals[key] += 1
    # Original publisher test split; keep exact spans, including source spelling.
    for i, line in enumerate((source / 'btx-test.jsonl').read_text('utf-8').splitlines()):
        row = json.loads(line)
        if all(s['category'] in {'private_person', 'private_address'} for s in row['label']):
            spans = [{'start': s['start'], 'end': s['end'], 'type': 'PERSON' if s['category'] == 'private_person' else 'ADDRESS'} for s in row['label']]
            add('btx-test', i, 'tr', row['text'], spans)
    # This publisher has only a train-labelled split. Preserve that fact in provenance.
    for i, line in enumerate((source / 'tr_privacy_tr_curated.jsonl').read_text('utf-8').splitlines()):
        row = json.loads(line)
        if not row['spans']:
            add('yusuf-train-clean', i, 'tr', row['text'], [], row['info']['id'])
    with zipfile.ZipFile(source / 'privy-dataset.zip') as archive:
        item = archive.getinfo('test-small.json')
        if item.file_size > 160 * 1024 * 1024:
            raise ArtifactError('PUBLIC_CORPUS_LIMIT')
        rows = json.load(archive.open(item))
    rejected = 0
    for i, row in enumerate(rows):
        spans = privy_spans(row)
        if spans is None:
            rejected += 1
        else:
            add('privy-test-small', i, 'en', row['full_text'], spans, row['template_id'])
    if any(totals[f'{lang}:{kind}'] != count for lang in ['tr', 'en'] for kind in ['PERSON', 'ADDRESS', 'clean']):
        raise ArtifactError('PUBLIC_CORPUS_COVERAGE')
    provenance = {'schemaVersion': 1, 'purpose': 'public-synthetic-comparison', 'independentCorporate': False,
                  'selection': 'first eligible documents in source order; before inference; no text/span edits',
                  'counts': dict(totals), 'privyRowsExcluded': rejected,
                  'splits': {'trPositive': 'BTX24 test', 'trClean': 'yusuf-said train-labelled; not publisher heldout', 'en': 'beki/privy test-small'},
                  'trainingOverlap': 'not verified against model publishers', 'datasets': lock['datasets']}
    return selected, provenance


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--count', type=int, default=100)
    parser.add_argument('--download', action='store_true', help='Connected staging only; pinned data and cards.')
    args = parser.parse_args()
    try:
        lock = json.loads(Path(__file__).with_name('public-corpora.lock.json').read_text('utf-8'))
        if args.download:
            args.source_directory.mkdir(parents=True, exist_ok=True)
            for dataset in lock['datasets']:
                for name, spec in dataset['files'].items():
                    download_file(f"https://huggingface.co/datasets/{dataset['repository']}/resolve/{dataset['revision']}/{spec['source']}", args.source_directory / name, spec)
        rows, provenance = build(args.source_directory, lock, args.count)
        with args.output.open('x', encoding='utf-8', newline='\n') as output:
            for row in rows:
                output.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
        provenance['corpusSha256'] = sha256_file(args.output)
        with args.output.with_suffix('.provenance.json').open('x', encoding='utf-8') as output:
            json.dump(provenance, output, ensure_ascii=False, indent=2)
            output.write('\n')
        print(json.dumps({'samples': len(rows), 'counts': provenance['counts'], 'independentCorporate': False, 'corpusSha256': provenance['corpusSha256']}))
    except Exception:
        raise SystemExit('PUBLIC_CORPUS_BUILD_FAILED')
