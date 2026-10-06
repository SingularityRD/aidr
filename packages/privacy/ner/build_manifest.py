#!/usr/bin/env python3
"""Build an inventory from pre-downloaded, licensed, reviewed local models.
This does NOT download models or establish that they are trustworthy.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from artifacts import ArtifactError, sha256_file, verified_manifest

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True, help='Local JSON configuration with model directories and label maps')
    parser.add_argument('--output', type=Path, required=True, help='Output manifest; directories resolve relative to this path')
    args = parser.parse_args()
    config = json.loads(args.config.read_text('utf-8'))
    for spec in config['models']:
        if spec.get('aggregation', 'token') not in ('token', 'first_word'):
            raise ArtifactError('INVALID_AGGREGATION')
        root = args.output.parent / spec['directory']
        spec['files'] = {p.relative_to(root).as_posix(): sha256_file(p) for p in sorted(root.rglob('*')) if p.is_file()}
    args.output.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    digest = sha256_file(args.output)
    verified_manifest(args.output, digest)
    print(digest)

if __name__ == '__main__':
    main()
